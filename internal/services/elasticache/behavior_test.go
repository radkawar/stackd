package elasticache

import (
	"context"
	"encoding/json"
	"errors"
	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/elasticache"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
	"testing"
	"time"
)

type testAuthority struct{ denied bool }

func (a *testAuthority) Authorize(context.Context, authorization.Request) *awswire.Error {
	if a.denied {
		return failure("AccessDenied", "Denied by current authority.")
	}
	return nil
}

type auditCapture struct{ calls []journal.APICallCompleted }

func (a *auditCapture) Record(_ context.Context, _ journal.Envelope, v journal.APICallCompleted) error {
	a.calls = append(a.calls, v)
	return nil
}
func cacheContext(ctx context.Context) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
}
func TestParameterMutationRollsBackAllAttachedIntent(t *testing.T) {
	ctx := cacheContext(t.Context())
	sc := scopeFor(ctx)
	repo := NewMemoryRepository(nil)
	now := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
	s := New(Config{Repository: repo, Clock: clock.NewManual(now), Authorizer: &testAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	group := ParameterGroup{Key: Key{Scope: sc, Kind: "parametergroup", Name: "shared"}, Family: "valkey8", Parameters: map[string]string{"timeout": "20"}}
	if e := repo.Update(ctx, func(tx Transaction) error {
		if e := tx.PutParameterGroup(group); e != nil {
			return e
		}
		for _, v := range []Cluster{{Key: Key{Scope: sc, Kind: "cluster", Name: "first"}, RuntimeID: "one", ParameterGroup: "shared", Status: "available", Version: 7, Parameters: map[string]string{"timeout": "20"}}, {Key: Key{Scope: sc, Kind: "cluster", Name: "second"}, RuntimeID: "two", ParameterGroup: "shared", Status: "rebooting", Version: 9}} {
			if e := tx.PutCluster(v); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	e := repo.Attempt(ctx, func(tx Transaction) error {
		_, e := s.modifyParameterGroup(ctx, tx, &api.ModifyCacheParameterGroupMessage{CacheParameterGroupName: new(api.String("shared")), ParameterNameValues: api.ParameterNameValueList{{ParameterName: new(api.String("timeout")), ParameterValue: new(api.String("60"))}}})
		return e
	})
	if e == nil {
		t.Fatal("busy attached cache accepted a partial parameter transition")
	}
	if e = repo.View(ctx, func(r Reader) error {
		p, e := r.ParameterGroup(group.Key)
		if e != nil {
			return e
		}
		v, e := r.Cluster(Key{Scope: sc, Kind: "cluster", Name: "first"})
		if e != nil {
			return e
		}
		if p.Parameters["timeout"] != "20" || v.Parameters["timeout"] != "20" || v.Status != "available" || v.Version != 7 || !v.Due.IsZero() {
			t.Fatalf("failed admission partially committed: group=%#v cluster=%#v", p, v)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestCurrentAuthorityAndCredentialRedaction(t *testing.T) {
	ctx := cacheContext(t.Context())
	authority := &testAuthority{}
	audit := &auditCapture{}
	s := New(Config{Authorizer: authority, Recorder: audit})
	t.Cleanup(func() { _ = s.Close() })
	password := "test-credential-never-retain"
	in := &api.CreateUserMessage{UserId: new(api.UserId("reader")), UserName: new(api.UserName("reader")), Engine: new(api.EngineType("VALKEY")), AccessString: new(api.AccessString("on ~app:* -@all +get")), AuthenticationMode: &api.AuthenticationMode{Type: new(api.InputAuthenticationType("password")), Passwords: api.PasswordListInput{api.String(password)}}}
	model, _ := awscatalog.LookupService("elasticache")
	op, _ := model.Operation("CreateUser")
	out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if value(out.(*api.User).Engine) != "valkey" {
		t.Fatal("engine casing was not normalized")
	}
	if e := s.repository.View(ctx, func(r Reader) error {
		v, e := r.User(Key{Scope: scopeFor(ctx), Kind: "user", Name: "reader"})
		if e != nil {
			return e
		}
		if len(v.PasswordHashes) != 1 || v.PasswordHashes[0] != hashPassword(password) {
			t.Fatal("credential was not retained as a SHA-256 digest")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	authority.denied = true
	modify, _ := model.Operation("ModifyUser")
	_, rejected = s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: modify, Input: &api.ModifyUserMessage{UserId: in.UserId, AccessString: new(api.AccessString("on ~* +@all"))}})
	if rejected == nil || rejected.Code != "AccessDenied" {
		t.Fatalf("revoked caller changed an existing user: %v", rejected)
	}
	body, e := json.Marshal(audit.calls)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(body), password) || !strings.Contains(string(body), "reader") {
		t.Fatal("API events leaked a credential or discarded resource identity")
	}
	var request struct {
		AuthenticationMode struct {
			Passwords []string `json:"passwords"`
		} `json:"authenticationMode"`
	}
	if e = json.Unmarshal(audit.calls[0].RequestParameters, &request); e != nil {
		t.Fatal(e)
	}
	if len(request.AuthenticationMode.Passwords) != 1 || request.AuthenticationMode.Passwords[0] != "HIDDEN_DUE_TO_SECURITY_REASONS" {
		t.Fatal("native audit password-list redaction shape was not preserved")
	}
	var response struct {
		UserID string `json:"userId"`
	}
	if e = json.Unmarshal(audit.calls[0].ResponseElements, &response); e != nil || response.UserID != "reader" {
		t.Fatalf("successful user creation omitted its native audit response: %v", e)
	}
}
func TestStaleLifecycleSelectionCannotTouchRecreatedName(t *testing.T) {
	ctx := cacheContext(t.Context())
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	k := Key{Scope: scopeFor(ctx), Kind: "cluster", Name: "reused"}
	v := Cluster{Key: k, RuntimeID: "new-incarnation", Version: 9, Due: now, Status: "creating", Operation: "create"}
	if e := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutCluster(v) }); e != nil {
		t.Fatal(e)
	}
	if e := (clusterJobs{s}).Run(ctx, scheduler.Job{Key: k.ARN(), Version: 8, Due: now}); e != nil {
		t.Fatal(e)
	}
	if e := s.repository.View(ctx, func(r Reader) error {
		got, e := r.Cluster(k)
		if e != nil {
			return e
		}
		if got.RuntimeID != "new-incarnation" || got.Version != 9 || got.Status != "creating" {
			t.Fatal("stale selection changed a recreated resource")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestUserGroupRequiresUniqueNativeNamesAndDefault(t *testing.T) {
	ctx := cacheContext(t.Context())
	s := New(Config{Authorizer: &testAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	sc := scopeFor(ctx)
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		for _, u := range []User{{Key: Key{Scope: sc, Kind: "user", Name: "first"}, Name: "reader", Engine: "valkey", Status: "active"}, {Key: Key{Scope: sc, Kind: "user", Name: "second"}, Name: "reader", Engine: "valkey", Status: "active"}} {
			if e := tx.PutUser(u); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	for _, ids := range [][]string{{"first"}, {"first", "second"}} {
		e := s.repository.View(ctx, func(r Reader) error {
			return s.validateMembers(ctx, r, "CreateUserGroup", UserGroup{Key: Key{Scope: sc, Kind: "usergroup", Name: "group"}, Engine: "valkey", UserIDs: ids})
		})
		var rejected *awswire.Error
		if !errors.As(e, &rejected) {
			t.Fatalf("invalid group accepted: %v", e)
		}
		expected := "DefaultUserRequired"
		if len(ids) == 2 {
			expected = "DuplicateUserName"
		}
		if rejected.Code != expected {
			t.Fatalf("got %s, want %s", rejected.Code, expected)
		}
	}
}

func TestDeletingUserWaitsForEveryAttachedACL(t *testing.T) {
	ctx := cacheContext(t.Context())
	sc := scopeFor(ctx)
	s := New(Config{Authorizer: &testAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	userKey := Key{Scope: sc, Kind: "user", Name: "reader"}
	groupKey := Key{Scope: sc, Kind: "usergroup", Name: "shared"}
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		if e := tx.PutUser(User{Key: userKey, Name: "reader", Engine: "valkey", Status: "active"}); e != nil {
			return e
		}
		if e := tx.PutUser(User{Key: Key{Scope: sc, Kind: "user", Name: "restricted-default"}, Name: "default", Engine: "valkey", Status: "active", NoPassword: true, AccessString: "off -@all"}); e != nil {
			return e
		}
		if e := tx.PutUserGroup(UserGroup{Key: groupKey, Engine: "valkey", Status: "active", UserIDs: []string{"reader", "restricted-default"}}); e != nil {
			return e
		}
		for _, name := range []string{"first", "second"} {
			if e := tx.PutCluster(Cluster{Key: Key{Scope: sc, Kind: "replicationgroup", Name: name}, RuntimeID: name, Status: "available", UserGroup: "shared"}); e != nil {
				return e
			}
		}
		_, e := s.deleteUser(ctx, tx, &api.DeleteUserMessage{UserId: new(api.UserId("reader"))})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	for index, name := range []string{"first", "second"} {
		if e := s.repository.Update(ctx, func(tx Transaction) error {
			v, e := tx.Cluster(Key{Scope: sc, Kind: "replicationgroup", Name: name})
			if e != nil {
				return e
			}
			v.Status = "available"
			if e = tx.PutCluster(v); e != nil {
				return e
			}
			return s.finishACL(tx, sc)
		}); e != nil {
			t.Fatal(e)
		}
		if e := s.repository.View(ctx, func(r Reader) error {
			user, e := r.User(userKey)
			if index == 0 {
				if e != nil || user.Status != "deleting" {
					t.Fatalf("user retired before every native ACL completed: user=%#v err=%v", user, e)
				}
			} else {
				if !errors.Is(e, ErrNotFound) {
					t.Fatalf("completed deletion retained user: %v", e)
				}
				group, e := r.UserGroup(groupKey)
				if e != nil {
					return e
				}
				if len(group.UserIDs) != 1 || group.UserIDs[0] != "restricted-default" || group.Status != "active" {
					t.Fatalf("completed deletion retained membership: %#v", group)
				}
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
}

func TestUnknownParameterRejectsWithoutPartialMutation(t *testing.T) {
	ctx := cacheContext(t.Context())
	s := New(Config{Authorizer: &testAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	k := Key{Scope: scopeFor(ctx), Kind: "parametergroup", Name: "configured"}
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutParameterGroup(ParameterGroup{Key: k, Family: "valkey8", Parameters: map[string]string{"timeout": "20"}})
	}); e != nil {
		t.Fatal(e)
	}
	e := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.modifyParameterGroup(ctx, tx, &api.ModifyCacheParameterGroupMessage{
			CacheParameterGroupName: new(api.String(k.Name)),
			ParameterNameValues: api.ParameterNameValueList{
				{ParameterName: new(api.String("timeout")), ParameterValue: new(api.String("60"))},
				{ParameterName: new(api.String("stackd-missing-setting")), ParameterValue: new(api.String("1"))},
			},
		})
		return err
	})
	var rejected *awswire.Error
	if !errors.As(e, &rejected) || rejected.Code != "InvalidParameterValue" || rejected.StatusCode != 400 {
		t.Fatalf("unknown parameter error differs from native controls_valid fixture: %v", e)
	}
	if e = s.repository.View(ctx, func(r Reader) error {
		got, err := r.ParameterGroup(k)
		if err != nil {
			return err
		}
		if got.Parameters["timeout"] != "20" {
			t.Fatal("invalid parameter list partially mutated the group")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestUserPaginationAndSelectedDefaultUseNativeBounds(t *testing.T) {
	ctx := cacheContext(t.Context())
	s := New(Config{Authorizer: &testAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		for _, id := range []string{"alpha", "beta"} {
			if e := tx.PutUser(User{Key: Key{Scope: scopeFor(ctx), Kind: "user", Name: id}, Name: id, Engine: "redis", Status: "active"}); e != nil {
				return e
			}
		}
		first, e := s.describeUsers(ctx, tx, &api.DescribeUsersMessage{MaxRecords: new(api.IntegerOptional(1))})
		if e != nil {
			return e
		}
		if len(first.Users) != 1 || value(first.Users[0].UserId) != "alpha" || first.Marker == nil {
			t.Fatalf("first bounded page lost ordering or continuation: %#v", first)
		}
		second, e := s.describeUsers(ctx, tx, &api.DescribeUsersMessage{MaxRecords: new(api.IntegerOptional(1)), Marker: first.Marker})
		if e != nil {
			return e
		}
		if len(second.Users) != 1 || value(second.Users[0].UserId) != "beta" {
			t.Fatalf("continuation repeated or skipped a user: %#v", second)
		}
		alien := awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"})
		if _, err := s.describeUsers(alien, tx, &api.DescribeUsersMessage{Marker: first.Marker, MaxRecords: new(api.IntegerOptional(1))}); err == nil {
			t.Fatal("pagination marker crossed account scope")
		}
		selected, e := s.describeUsers(ctx, tx, &api.DescribeUsersMessage{UserId: new(api.UserId("default")), MaxRecords: new(api.IntegerOptional(0))})
		if e != nil {
			return e
		}
		if len(selected.Users) != 1 || value(selected.Users[0].UserId) != "default" || selected.Users[0].Authentication.PasswordCount != nil || selected.Marker != nil {
			t.Fatalf("selected service-provided user inherited list pagination or password metadata: %#v", selected)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestKnownReplicationMemberRejectsUnsupportedMutation(t *testing.T) {
	ctx := cacheContext(t.Context())
	s := New(Config{Authorizer: &testAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		v := Cluster{Key: Key{Scope: scopeFor(ctx), Kind: "replicationgroup", Name: "owned"}, Shards: 1, Replicas: 1, Status: "available"}
		if e := tx.PutCluster(v); e != nil {
			return e
		}
		_, e := s.rebootCluster(ctx, tx, &api.RebootCacheClusterMessage{CacheClusterId: new(api.String("owned-0002")), CacheNodeIdsToReboot: api.CacheNodeIdsList{api.String("0001")}})
		var rejected *awswire.Error
		if !errors.As(e, &rejected) || rejected.Code != "InvalidParameterCombination" {
			t.Fatalf("known member was lost or reboot silently widened to its whole group: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestModeledMissingResourceErrorsRemainSDKRecognizable(t *testing.T) {
	ctx := cacheContext(t.Context())
	s := New(Config{Authorizer: &testAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	model, _ := awscatalog.LookupService("elasticache")
	for _, row := range []struct {
		action string
		in     any
		code   string
		status int
	}{
		{"DescribeSnapshots", &api.DescribeSnapshotsMessage{SnapshotName: new(api.String("absent"))}, "SnapshotNotFoundFault", 404},
		{"DescribeReplicationGroups", &api.DescribeReplicationGroupsMessage{ReplicationGroupId: new(api.String("absent"))}, "ReplicationGroupNotFoundFault", 404},
		{"DescribeCacheSubnetGroups", &api.DescribeCacheSubnetGroupsMessage{CacheSubnetGroupName: new(api.String("absent"))}, "CacheSubnetGroupNotFoundFault", 400},
	} {
		op, _ := model.Operation(row.action)
		_, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: row.in})
		if rejected == nil || rejected.Code != row.code || rejected.StatusCode != row.status {
			t.Fatalf("%s lost its modeled error identity: %v", row.action, rejected)
		}
	}
}

func TestSDKPasswordlessAuthenticationMode(t *testing.T) {
	ctx := cacheContext(t.Context())
	s := New(Config{Authorizer: &testAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	model, _ := awscatalog.LookupService("elasticache")
	op, _ := model.Operation("CreateUser")
	out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: &api.CreateUserMessage{
		UserId: new(api.UserId("disabled-default")), UserName: new(api.UserName("default")), Engine: new(api.EngineType("valkey")),
		AccessString: new(api.AccessString("off -@all")), AuthenticationMode: &api.AuthenticationMode{Type: new(api.InputAuthenticationTypeNO_PASSWORD)},
	}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	user := out.(*api.User)
	if user.Authentication == nil || user.Authentication.Type == nil || *user.Authentication.Type != api.AuthenticationTypeNO_PASSWORD || user.Authentication.PasswordCount != nil {
		t.Fatalf("passwordless admission claimed password credentials: %#v", user.Authentication)
	}
}

func TestBuiltinParameterGroupsAreScopedAndImmutable(t *testing.T) {
	ctx := cacheContext(t.Context())
	authority := &testAuthority{}
	s := New(Config{Authorizer: authority})
	t.Cleanup(func() { _ = s.Close() })
	model, _ := awscatalog.LookupService("elasticache")
	command := func(action string, in any) (any, *awswire.Error) {
		op, _ := model.Operation(action)
		return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: in})
	}
	listed, rejected := command("DescribeCacheParameterGroups", &api.DescribeCacheParameterGroupsMessage{})
	if rejected != nil {
		t.Fatal(rejected)
	}
	for _, group := range listed.(*api.CacheParameterGroupsMessage).CacheParameterGroups {
		if !strings.HasPrefix(value(group.ARN), "arn:aws:elasticache:us-east-1:111111111111:parametergroup:") {
			t.Fatalf("builtin escaped the caller's scope: %s", value(group.ARN))
		}
		if _, rejected = command("DescribeCacheParameters", &api.DescribeCacheParametersMessage{CacheParameterGroupName: group.CacheParameterGroupName}); rejected != nil {
			t.Fatalf("listed group cannot resolve its parameters: %v", rejected)
		}
	}
	name := new(api.String("default.valkey8.cluster.on"))
	for _, row := range []struct {
		action string
		in     any
	}{
		{"ModifyCacheParameterGroup", &api.ModifyCacheParameterGroupMessage{CacheParameterGroupName: name, ParameterNameValues: api.ParameterNameValueList{{ParameterName: new(api.String("timeout")), ParameterValue: new(api.String("20"))}}}},
		{"ResetCacheParameterGroup", &api.ResetCacheParameterGroupMessage{CacheParameterGroupName: name, ResetAllParameters: new(api.Boolean(true))}},
		{"DeleteCacheParameterGroup", &api.DeleteCacheParameterGroupMessage{CacheParameterGroupName: name}},
		{"AddTagsToResource", &api.AddTagsToResourceMessage{ResourceName: new(api.String("arn:aws:elasticache:us-east-1:111111111111:parametergroup:default.valkey8.cluster.on")), Tags: api.TagList{{Key: new(api.String("mutate")), Value: new(api.String("no"))}}}},
	} {
		_, rejected = command(row.action, row.in)
		if rejected == nil || rejected.Code != "InvalidCacheParameterGroupState" {
			t.Fatalf("%s altered an immutable native default: %v", row.action, rejected)
		}
	}
	described, rejected := command("DescribeCacheParameters", &api.DescribeCacheParametersMessage{CacheParameterGroupName: name, Source: new(api.String("system"))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	timeout := ""
	for _, p := range described.(*api.CacheParameterGroupDetails).Parameters {
		if value(p.ParameterName) == "timeout" {
			timeout = value(p.ParameterValue)
		}
	}
	if timeout != "0" {
		t.Fatalf("rejected mutations changed the effective default timeout: %q", timeout)
	}
	authority.denied = true
	if _, rejected = command("DescribeCacheParameters", &api.DescribeCacheParametersMessage{CacheParameterGroupName: name}); rejected == nil || rejected.Code != "AccessDenied" {
		t.Fatalf("builtin descriptions bypassed current IAM: %v", rejected)
	}
}

func TestModifyPreservesDisabledSnapshotAdmission(t *testing.T) {
	for _, kind := range []string{"cluster", "replicationgroup"} {
		for _, test := range []struct {
			name      string
			retention api.IntegerOptional
		}{{"disabled", 0}, {"unsupported-enabled", 1}} {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				ctx := cacheContext(t.Context())
				repository := NewMemoryRepository(nil)
				key := Key{Scope: scopeFor(ctx), Kind: kind, Name: "cache"}
				original := Cluster{Key: key, RuntimeID: "retained", Status: "available", Version: 7}
				if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutCluster(original) }); err != nil {
					t.Fatal(err)
				}
				service := New(Config{Repository: repository, Authorizer: &testAuthority{}})
				t.Cleanup(func() { _ = service.Close() })
				err := repository.Attempt(ctx, func(tx Transaction) error {
					if kind == "cluster" {
						_, err := service.modifyCluster(ctx, tx, &api.ModifyCacheClusterMessage{CacheClusterId: new(api.String(key.Name)), ApplyImmediately: new(api.Boolean(true)), SnapshotRetentionLimit: &test.retention})
						return err
					}
					_, err := service.modifyReplicationGroup(ctx, tx, &api.ModifyReplicationGroupMessage{ReplicationGroupId: new(api.String(key.Name)), ApplyImmediately: new(api.Boolean(true)), SnapshotRetentionLimit: &test.retention})
					return err
				})
				if test.retention == 0 && err != nil {
					t.Fatalf("disabled snapshot echo rejected: %v", err)
				}
				if test.retention != 0 && (err == nil || wireError(err).Code != "InvalidParameterCombination") {
					t.Fatalf("unsupported snapshots admitted: %v", err)
				}
				if err := repository.View(ctx, func(r Reader) error {
					current, err := r.Cluster(key)
					if err != nil {
						return err
					}
					if test.retention == 0 {
						if current.Status != "modifying" || current.Version != original.Version+1 {
							t.Fatalf("accepted modification was not scheduled: %+v", current)
						}
					} else if current.Status != original.Status || current.Version != original.Version || !current.Due.IsZero() {
						t.Fatalf("rejected modification changed intent: %+v", current)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
