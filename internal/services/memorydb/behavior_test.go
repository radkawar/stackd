package memorydb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"stackd/clock"
	engine "stackd/engine/valkey"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/memorydb"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/journal"
	"strings"
	"testing"
	"time"
)

type auditCapture struct{ calls []journal.APICallCompleted }

func (a *auditCapture) Record(_ context.Context, _ journal.Envelope, c journal.APICallCompleted) error {
	a.calls = append(a.calls, c)
	return nil
}
func TestCredentialRejectionRedactsAuditAndHashesAuthentication(t *testing.T) {
	secret := "correct-horse-battery-staple"
	mode := &api.AuthenticationMode{Type: new(api.InputAuthenticationType("password")), Passwords: api.PasswordListInput{api.String(secret)}}
	kind, hashes, e := authentication(mode)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte(secret))
	if kind != "password" || len(hashes) != 1 || hashes[0] != hex.EncodeToString(sum[:]) {
		t.Fatalf("authentication did not retain only SHA256 credentials: %q %v", kind, hashes)
	}
	if _, _, err := authentication(&api.AuthenticationMode{Type: new(api.InputAuthenticationType("no-password"))}); err == nil {
		t.Fatal("custom user accepted the reserved default-user authentication mode")
	}
	recorder := &auditCapture{}
	s := New(Config{Recorder: recorder})
	t.Cleanup(func() { _ = s.Close() })
	model, _ := awscatalog.LookupService("memorydb")
	op, _ := model.Operation("CreateUser")
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	input := &api.CreateUserRequest{UserName: new(api.UserName("owned")), AccessString: new(api.AccessString("on ~* +get")), AuthenticationMode: mode}
	if e = s.RecordRequestError(ctx, awsapi.DecodedRequest{Operation: op, Input: input}, invalid("Rejected credentials.")); e != nil {
		t.Fatal(e)
	}
	if len(recorder.calls) != 1 {
		t.Fatalf("expected one audit event, got %d", len(recorder.calls))
	}
	body, e := json.Marshal(recorder.calls[0])
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(body), secret) || strings.Contains(string(body), hashes[0]) {
		t.Fatal("credentials escaped into audit")
	}
	if !strings.Contains(string(body), "owned") {
		t.Fatal("audit discarded resource identity")
	}
}

type mutableAuthority struct{ denied bool }

func (a *mutableAuthority) Authorize(context.Context, authorization.Request) *awswire.Error {
	if a.denied {
		return failure("AccessDeniedException", "Denied")
	}
	return nil
}
func TestTagMutationUsesCurrentAuthorityAndScopedARN(t *testing.T) {
	authority := &mutableAuthority{}
	s := New(Config{Authorizer: authority})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	k := Key{Scope: scopeFor(ctx), Kind: "cluster", Name: "owned"}
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutCluster(Cluster{Key: k, Tags: map[string]string{"env": "original"}})
	}); e != nil {
		t.Fatal(e)
	}
	authority.denied = true
	e := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, e := s.tagResource(tx.Context(), tx, &api.TagResourceRequest{ResourceArn: new(api.String(k.ARN())), Tags: api.TagList{{Key: new(api.String("env")), Value: new(api.String("changed"))}}})
		return e
	})
	var rejected *awswire.Error
	if !errors.As(e, &rejected) || rejected.Code != "AccessDeniedException" {
		t.Fatalf("revoked authority accepted tag update: %v", e)
	}
	if e = s.repository.View(ctx, func(r Reader) error {
		v, e := r.Cluster(k)
		if e != nil {
			return e
		}
		if v.Tags["env"] != "original" {
			t.Fatal("denied command committed tags")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	foreign := k
	foreign.AccountID = "222222222222"
	if _, e = tagKey(ctx, foreign.ARN()); e == nil {
		t.Fatal("foreign account ARN entered local tag authority")
	}
}

type heldEnsure struct {
	Runtime
	entered chan struct{}
	release chan struct{}
	spec    chan engine.Specification
	err     error
}

func (r heldEnsure) Ensure(ctx context.Context, spec engine.Specification) (engine.Deployment, error) {
	if r.spec != nil {
		r.spec <- spec
	}
	close(r.entered)
	select {
	case <-ctx.Done():
		return engine.Deployment{}, ctx.Err()
	case <-r.release:
		if r.err != nil {
			return engine.Deployment{}, r.err
		}
		return engine.Deployment{Endpoint: engine.Endpoint{Address: "127.0.0.1", Port: 6379}}, nil
	}
}
func TestOldNativeCompletionCannotReadyNewIncarnation(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	native := heldEnsure{entered: make(chan struct{}), release: make(chan struct{})}
	s := New(Config{Runtime: native, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	k := Key{Scope: Scope{"aws", "111111111111", "us-east-1"}, Kind: "cluster", Name: "owned"}
	v := Cluster{Key: k, RuntimeID: "old-incarnation", Status: "creating", Operation: "create", Shards: 1, ACLName: "open-access", ParameterGroup: "default.memorydb-valkey7", Version: 1, Due: now}
	if e := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutCluster(v) }); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- (clusterJobs{s}).Run(t.Context(), scheduler.Job{Key: k.ARN(), Version: 1, Due: now}) }()
	<-native.entered
	v.RuntimeID = "new-incarnation"
	if e := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutCluster(v) }); e != nil {
		t.Fatal(e)
	}
	close(native.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := s.repository.View(t.Context(), func(r Reader) error {
		current, e := r.Cluster(k)
		if e != nil {
			return e
		}
		if current.RuntimeID != "new-incarnation" || current.Status != "creating" || current.Deployment.Endpoint.Address != "" {
			t.Fatalf("stale native completion changed recreated cluster: %#v", current)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func TestUserDeletionWaitsForAppliedACLRemoval(t *testing.T) {
	s := New(Config{Authorizer: &mutableAuthority{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	sc := scopeFor(ctx)
	u := User{Key: Key{Scope: sc, Kind: "user", Name: "owned"}, Status: "active", AccessString: "on ~* +get", Authentication: "no-password"}
	a := ACL{Key: Key{Scope: sc, Kind: "acl", Name: "application"}, Status: "active", Users: []string{"owned"}}
	c := Cluster{Key: Key{Scope: sc, Kind: "cluster", Name: "database"}, Status: "available", ACLName: a.Key.Name, Version: 1}
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		if e := tx.PutUser(u); e != nil {
			return e
		}
		if e := tx.PutACL(a); e != nil {
			return e
		}
		return tx.PutCluster(c)
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, e := s.deleteUser(tx.Context(), tx, &api.DeleteUserRequest{UserName: new(api.UserName(u.Key.Name))})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		if e := settleAccess(tx, sc); e != nil {
			return e
		}
		pending, e := tx.User(u.Key)
		if e != nil {
			return e
		}
		if pending.Status != "deleting" {
			t.Fatal("user deletion lost pending native intent")
		}
		acl, e := tx.ACL(a.Key)
		if e != nil {
			return e
		}
		if len(acl.Users) != 0 {
			t.Fatal("deleted user remains in desired ACL")
		}
		cluster, e := tx.Cluster(c.Key)
		if e != nil {
			return e
		}
		if cluster.Status != "updating" || cluster.Version != 2 {
			t.Fatal("ACL removal did not fence the live cluster")
		}
		cluster.Status = "available"
		if e = tx.PutCluster(cluster); e != nil {
			return e
		}
		if e = settleAccess(tx, sc); e != nil {
			return e
		}
		if _, e = tx.User(u.Key); !errors.Is(e, ErrNotFound) {
			t.Fatalf("completed removal kept user: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

// Cluster status follows the native application boundary, not the successful
// control-plane write. User "modifying" is captured in
// testdata/aws/valkey/memorydb_controls.json, memorydb-user-update; ACL
// "modifying" is documented at
// https://docs.aws.amazon.com/memorydb/latest/APIReference/API_ACL.html.
func TestClusterUpdatesWaitForNativeApplication(t *testing.T) {
	for _, mutation := range []struct {
		action, operation, timeout, access, userStatus, aclStatus string
		input                                                     any
		users                                                     int
	}{
		{
			action: "UpdateCluster", operation: "update", timeout: "73", access: "on ~app:* +get", users: 1, userStatus: "active", aclStatus: "active",
			input: &api.UpdateClusterRequest{ClusterName: new(api.String("database")), ParameterGroupName: new(api.String("replacement-parameters"))},
		},
		{
			action: "UpdateParameterGroup", operation: "parameters", timeout: "73", access: "on ~app:* +get", users: 1, userStatus: "active", aclStatus: "active",
			input: &api.UpdateParameterGroupRequest{ParameterGroupName: new(api.String("native-parameters")), ParameterNameValues: api.ParameterNameValueList{{ParameterName: new(api.String("timeout")), ParameterValue: new(api.String("73"))}}},
		},
		{
			action: "ResetParameterGroup", operation: "parameters", access: "on ~app:* +get", users: 1, userStatus: "active", aclStatus: "active",
			input: &api.ResetParameterGroupRequest{ParameterGroupName: new(api.String("native-parameters")), AllParameters: new(api.Boolean(true))},
		},
		{
			action: "UpdateACL", operation: "access", timeout: "37", userStatus: "active", aclStatus: "modifying",
			input: &api.UpdateACLRequest{ACLName: new(api.String("application")), UserNamesToRemove: api.UserNameListInput{api.UserName("owned")}},
		},
		{
			action: "UpdateUser", operation: "access", timeout: "37", access: "on ~app:* +get +set", users: 1, userStatus: "modifying", aclStatus: "modifying",
			input: &api.UpdateUserRequest{UserName: new(api.UserName("owned")), AccessString: new(api.AccessString("on ~app:* +get +set"))},
		},
		{
			action: "DeleteUser", operation: "access", timeout: "37", userStatus: "deleting", aclStatus: "modifying",
			input: &api.DeleteUserRequest{UserName: new(api.UserName("owned"))},
		},
	} {
		for _, outcome := range []struct {
			name        string
			err         error
			unavailable bool
		}{
			{name: "applied"},
			{name: "native-error", err: errors.New("native application failed")},
			{name: "runtime-unavailable", unavailable: true},
		} {
			t.Run(mutation.action+"/"+outcome.name, func(t *testing.T) {
				now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
				native := heldEnsure{entered: make(chan struct{}), release: make(chan struct{}), spec: make(chan engine.Specification, 1), err: outcome.err}
				s := New(Config{Authorizer: &mutableAuthority{}, Runtime: native, Clock: clock.NewManual(now)})
				t.Cleanup(func() { _ = s.Close() })
				// This regression explicitly drives one native job below. Prevent
				// after-commit Wake from concurrently running the same retained job.
				s.JobDriver().Close()
				ctx, cancel := context.WithCancel(awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}))
				t.Cleanup(cancel)
				sc := scopeFor(ctx)
				user := User{Key: Key{Scope: sc, Kind: "user", Name: "owned"}, Status: "active", AccessString: "on ~app:* +get", Authentication: "password", PasswordHashes: []string{strings.Repeat("a", 64)}}
				acl := ACL{Key: Key{Scope: sc, Kind: "acl", Name: "application"}, Status: "active", Users: []string{user.Key.Name}}
				oldEndpoint := engine.Endpoint{Address: "127.0.0.1", Port: 6378}
				cluster := Cluster{Key: Key{Scope: sc, Kind: "cluster", Name: "database"}, RuntimeID: "native-incarnation", Status: "available", Engine: "valkey", EngineVersion: engine.Version, NodeType: "db.t4g.small", Shards: 1, TLSEnabled: true, ACLName: acl.Key.Name, ParameterGroup: "native-parameters", Version: 1, Deployment: engine.Deployment{Endpoint: oldEndpoint, Nodes: []engine.Node{{ID: "native-primary", Endpoint: oldEndpoint}}}}
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					if err := tx.PutUser(user); err != nil {
						return err
					}
					if err := tx.PutACL(acl); err != nil {
						return err
					}
					for name, timeout := range map[string]string{"native-parameters": "37", "replacement-parameters": "73"} {
						if err := tx.PutParameterGroup(ParameterGroup{Key: Key{Scope: sc, Kind: "parametergroup", Name: name}, Family: "memorydb_valkey7", Parameters: map[string]string{"timeout": timeout}}); err != nil {
							return err
						}
					}
					return tx.PutCluster(cluster)
				}); err != nil {
					t.Fatal(err)
				}
				model, _ := awscatalog.LookupService("memorydb")
				operation, _ := model.Operation(mutation.action)
				output, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: mutation.input})
				if rejected != nil {
					t.Fatal(rejected)
				}
				if updated, ok := output.(*api.UpdateClusterResponse); ok && value(updated.Cluster.Status) != "updating" {
					t.Fatalf("UpdateCluster projected %q before native application", value(updated.Cluster.Status))
				}
				checkState := func(status, operation string, version int64, endpoint engine.Endpoint) {
					t.Helper()
					if err := s.repository.View(ctx, func(r Reader) error {
						current, err := r.Cluster(cluster.Key)
						if err != nil {
							return err
						}
						due := now
						if status != "updating" {
							due = now.Add(healthInterval)
						}
						if current.Status != status || current.Operation != operation || current.Version != version || current.RuntimeID != cluster.RuntimeID || !current.Due.Equal(due) {
							t.Fatalf("native lifecycle lost pending intent or fencing: %#v", current)
						}
						wantUser, wantACL := mutation.userStatus, mutation.aclStatus
						if status == "available" {
							wantUser, wantACL = "active", "active"
						}
						currentUser, err := r.User(user.Key)
						if status == "available" && mutation.action == "DeleteUser" {
							if !errors.Is(err, ErrNotFound) {
								t.Fatalf("applied removal retained user: %#v (%v)", currentUser, err)
							}
						} else if err != nil {
							return err
						} else if currentUser.Status != wantUser {
							t.Fatalf("user settled before native completion: got %q, want %q", currentUser.Status, wantUser)
						}
						currentACL, err := r.ACL(acl.Key)
						if err != nil {
							return err
						}
						if currentACL.Status != wantACL {
							t.Fatalf("ACL settled before native completion: got %q, want %q", currentACL.Status, wantACL)
						}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					describe, _ := model.Operation("DescribeClusters")
					output, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: describe, Protocol: model.Protocol, Input: &api.DescribeClustersRequest{ClusterName: new(api.String(cluster.Key.Name)), ShowShardDetails: new(api.BooleanOptional(true))}})
					if rejected != nil {
						t.Fatal(rejected)
					}
					rows := output.(*api.DescribeClustersResponse).Clusters
					if len(rows) != 1 || value(rows[0].Status) != status {
						t.Fatalf("DescribeClusters did not project %q: %#v", status, rows)
					}
					wantParameters := "applying"
					if status == "available" {
						wantParameters = "in-sync"
					}
					if value(rows[0].ParameterGroupStatus) != wantParameters {
						t.Fatalf("parameters settled before native completion: %#v", rows[0])
					}
					if endpoint.Address == "" {
						if rows[0].ClusterEndpoint != nil {
							t.Fatalf("failed application retained a ready endpoint: %#v", rows[0].ClusterEndpoint)
						}
					} else if rows[0].ClusterEndpoint == nil || value(rows[0].ClusterEndpoint.Address) != endpoint.Address || int32(*rows[0].ClusterEndpoint.Port) != endpoint.Port {
						t.Fatalf("cluster did not retain the actual native endpoint: %#v", rows[0].ClusterEndpoint)
					}
					if len(rows[0].Shards) != 1 {
						t.Fatalf("missing native shard: %#v", rows[0].Shards)
					}
					for _, shard := range rows[0].Shards {
						if value(shard.Status) != status {
							t.Fatalf("shard did not project %q: %#v", status, shard)
						}
						for _, node := range shard.Nodes {
							if value(node.Status) != status {
								t.Fatalf("node did not project %q: %#v", status, node)
							}
						}
						if status == "failed" && len(shard.Nodes) != 0 {
							t.Fatal("failed application retained native nodes")
						}
					}
				}
				checkState("updating", mutation.operation, 2, oldEndpoint)
				for _, guard := range []struct {
					action string
					input  any
				}{
					{"UpdateCluster", &api.UpdateClusterRequest{ClusterName: new(api.String(cluster.Key.Name)), Description: new(api.String("must not supersede pending work"))}},
					{"DeleteCluster", &api.DeleteClusterRequest{ClusterName: new(api.String(cluster.Key.Name))}},
					{"CreateSnapshot", &api.CreateSnapshotRequest{ClusterName: new(api.String(cluster.Key.Name)), SnapshotName: new(api.String("pending-snapshot"))}},
				} {
					operation, _ := model.Operation(guard.action)
					if _, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: guard.input}); rejected == nil || rejected.Code != "InvalidClusterStateFault" {
						t.Fatalf("%s admitted an updating cluster: %v", guard.action, rejected)
					}
				}
				jobs := clusterJobs{s}
				job, found, err := jobs.Next(ctx)
				if err != nil || !found || job.Key != cluster.Key.ARN() || job.Version != 2 || !job.Due.Equal(now) {
					t.Fatalf("updating cluster lost its native job: %#v, %t, %v", job, found, err)
				}
				if outcome.unavailable {
					s.runtime = nil
					if err := jobs.Run(ctx, job); err != nil {
						t.Fatal(err)
					}
				} else {
					done := make(chan error, 1)
					go func() { done <- jobs.Run(ctx, job) }()
					select {
					case <-native.entered:
					case err := <-done:
						t.Fatalf("cluster job returned before native application: %v", err)
					}
					spec := <-native.spec
					if spec.ID != cluster.RuntimeID || spec.Parameters["timeout"] != mutation.timeout || len(spec.Users) != mutation.users || !spec.TLSEnabled || !spec.ClusterMode || spec.Shards != 1 {
						t.Fatalf("job did not apply desired native configuration: %#v", spec)
					}
					if len(spec.Users) == 1 && (spec.Users[0].Name != user.Key.Name || spec.Users[0].AccessString != mutation.access || spec.Users[0].NoPassword || len(spec.Users[0].PasswordHashes) != 1 || spec.Users[0].PasswordHashes[0] != user.PasswordHashes[0]) {
						t.Fatalf("job did not apply desired native ACL: %#v", spec.Users)
					}
					checkState("updating", mutation.operation, 2, oldEndpoint)
					close(native.release)
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				}
				if outcome.err != nil || outcome.unavailable {
					checkState("failed", mutation.operation, 3, engine.Endpoint{})
				} else {
					checkState("available", "", 3, engine.Endpoint{Address: "127.0.0.1", Port: 6379})
				}
			})
		}
	}
}
