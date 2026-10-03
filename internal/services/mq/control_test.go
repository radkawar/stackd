package mq

import (
	"context"
	"errors"
	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/mq"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"testing"
	"time"
)

type testAuthorizer struct {
	deny       bool
	requestTag bool
}

func (a *testAuthorizer) Authorize(_ context.Context, r authorization.Request) *awswire.Error {
	tag := r.Context["aws:RequestTag/team"]
	if a.deny || a.requestTag && (len(tag) != 1 || tag[0] != "green") {
		return failure("ForbiddenException", "Denied", 403)
	}
	return nil
}

type testRuntime struct {
	reboot func(context.Context, BrokerRecord) (Endpoint, error)
}

func (r testRuntime) Ensure(context.Context, BrokerRecord) (Endpoint, error) {
	return Endpoint{Address: "ssl://127.0.0.1:1234", NativeID: "owned", CAPEM: []byte("ca")}, nil
}
func (r testRuntime) Reboot(ctx context.Context, v BrokerRecord) (Endpoint, error) {
	if r.reboot != nil {
		return r.reboot(ctx, v)
	}
	return r.Ensure(ctx, v)
}
func (testRuntime) Delete(context.Context, BrokerRecord) error { return nil }
func (testRuntime) Close() error                               { return nil }
func controlFixture(t *testing.T) (*Service, context.Context, BrokerRecord) {
	t.Helper()
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now), Authorizer: &testAuthorizer{}, Runtime: testRuntime{}})
	t.Cleanup(func() { _ = s.Close() })
	v := BrokerRecord{Scope: Scope{"aws", "123456789012", "us-east-1"}, ID: "b-owned", ARN: "arn:aws:mq:us-east-1:123456789012:broker:owned:b-owned", Name: "owned", Engine: "ACTIVEMQ", EngineVersion: "5.18", InstanceType: "mq.t3.micro", State: "RUNNING", Version: 1, Created: now, Due: now, Tags: map[string]string{}, Users: []UserRecord{{Username: "initial", Password: "old-password-123"}}, MaintenanceDay: "WEDNESDAY", MaintenanceTime: "00:01", MaintenanceZone: "UTC"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region})
	if e := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutBroker(v) }); e != nil {
		t.Fatal(e)
	}
	return s, ctx, v
}
func storedBroker(t *testing.T, s *Service, v BrokerRecord) BrokerRecord {
	t.Helper()
	var out BrokerRecord
	if e := s.repository.View(t.Context(), func(r Reader) error { var e error; out, e = r.Broker(v.Scope, v.ID); return e }); e != nil {
		t.Fatal(e)
	}
	return out
}
func TestUserPendingCommitRequiresSuccessfulNativeReboot(t *testing.T) {
	for _, tc := range []struct {
		name      string
		effective bool
		pending   bool
		legacy    bool
	}{
		{name: "console-grant", pending: true},
		{name: "console-revoke", effective: true},
		{name: "legacy-console-grant", pending: true, legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx, v := controlFixture(t)
			v.Users[0].ConsoleAccess = tc.effective
			oldPassword, newPassword := "old-password-123", "new-password-456"
			if tc.legacy {
				oldPassword, newPassword = "", ""
				v.Users[0].Password = ""
			}
			if e := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutBroker(v) }); e != nil {
				t.Fatal(e)
			}
			in := &api.UpdateUserInput{}
			text(&in.BrokerId, v.ID)
			text(&in.Username, "initial")
			boolean(&in.ConsoleAccess, tc.pending)
			if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.updateUser(tx.Context(), tx, in); return e }); e != nil {
				t.Fatal(e)
			}
			if !tc.legacy {
				in.ConsoleAccess = nil
				text(&in.Password, newPassword)
				if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.updateUser(tx.Context(), tx, in); return e }); e != nil {
					t.Fatal(e)
				}
			}
			pending := storedBroker(t, s, v)
			u := pending.Users[0]
			if u.Password != oldPassword || u.PendingPassword != newPassword || u.ConsoleAccess != tc.effective || u.PendingConsoleAccess != tc.pending {
				t.Fatalf("admission changed effective authority or lost pending changes: %+v", u)
			}
			describe := &api.DescribeUserInput{}
			text(&describe.BrokerId, v.ID)
			text(&describe.Username, "initial")
			if e := s.repository.Attempt(ctx, func(tx Transaction) error {
				out, e := s.describeUser(tx.Context(), tx, describe)
				if e == nil && (out.ConsoleAccess == nil || truth(out.ConsoleAccess) != tc.effective || out.Pending == nil || out.Pending.ConsoleAccess == nil || truth(out.Pending.ConsoleAccess) != tc.pending) {
					t.Fatalf("DescribeUser lost effective/pending console boundary: %+v", out)
				}
				return e
			}); e != nil {
				t.Fatal(e)
			}
			s.runtime = testRuntime{reboot: func(context.Context, BrokerRecord) (Endpoint, error) {
				return Endpoint{}, errors.New("native config rejected")
			}}
			reboot := &api.RebootBrokerInput{}
			text(&reboot.BrokerId, v.ID)
			if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.rebootBroker(tx.Context(), tx, reboot); return e }); e != nil {
				t.Fatal(e)
			}
			j := brokerJobs{s}
			job, _, e := j.Next(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if e = j.Run(ctx, job); e != nil {
				t.Fatal(e)
			}
			failed := storedBroker(t, s, v)
			u = failed.Users[0]
			if failed.State != "CRITICAL_ACTION_REQUIRED" || u.Password != oldPassword || u.ConsoleAccess != tc.effective || u.PendingChange != "UPDATE" || u.PendingPassword != newPassword || u.PendingConsoleAccess != tc.pending {
				t.Fatalf("failed native effect changed effective authority or lost pending changes: %+v", u)
			}
			s.runtime = testRuntime{}
			s.clock.(*clock.Manual).Advance(30 * time.Second)
			job, _, e = j.Next(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if e = j.Run(ctx, job); e != nil {
				t.Fatal(e)
			}
			done := storedBroker(t, s, v)
			u = done.Users[0]
			if done.State != "RUNNING" || u.Password != newPassword || u.ConsoleAccess != tc.pending || u.PendingChange != "" || u.PendingPassword != "" || u.PendingConsoleAccess {
				t.Fatalf("successful reboot did not commit and clear pending authority: %+v", u)
			}
		})
	}
}
func TestMaintenanceAndStaleProbeFence(t *testing.T) {
	s, ctx, v := controlFixture(t)
	j := brokerJobs{s}
	stale, _, e := j.Next(ctx)
	if e != nil {
		t.Fatal(e)
	}
	in := &api.DeleteUserInput{}
	text(&in.BrokerId, v.ID)
	text(&in.Username, "initial")
	if e = s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.deleteUser(tx.Context(), tx, in); return e }); e != nil {
		t.Fatal(e)
	}
	if e = j.Run(ctx, stale); e != nil {
		t.Fatal(e)
	}
	pending := storedBroker(t, s, v)
	if pending.Users[0].PendingChange != "DELETE" || pending.State != "RUNNING" {
		t.Fatal("stale probe overwrote pending intent")
	}
	s.clock.(*clock.Manual).Advance(time.Minute)
	job, _, e := j.Next(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Run(ctx, job); e != nil {
		t.Fatal(e)
	}
	claimed := storedBroker(t, s, v)
	if claimed.State != "REBOOT_IN_PROGRESS" {
		t.Fatal("maintenance did not claim real reboot")
	}
	job, _, e = j.Next(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Run(ctx, job); e != nil {
		t.Fatal(e)
	}
	done := storedBroker(t, s, v)
	if len(brokerUsers(done)) != 0 || done.State != "RUNNING" {
		t.Fatal("last deleted user resurrected")
	}
}
func TestScopeARNAndAuthorityBoundaries(t *testing.T) {
	s, ctx, v := controlFixture(t)
	for _, sc := range []Scope{{"aws-cn", v.AccountID, v.Region}, {v.Partition, "222222222222", v.Region}, {v.Partition, v.AccountID, "us-west-2"}} {
		foreign := awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
		if e := s.repository.View(foreign, func(r Reader) error { _, e := s.load(r.Context(), r, v.ID, "DescribeBroker"); return e }); !errors.Is(e, ErrNotFound) {
			t.Fatalf("cross-scope load: %v", e)
		}
	}
	if e := s.repository.View(ctx, func(r Reader) error {
		_, e := s.load(r.Context(), r, "arn:aws:mq:us-east-1:123456789012:broker:forged:b-owned", "DescribeBroker")
		return e
	}); !errors.Is(e, ErrNotFound) {
		t.Fatalf("forged name ARN accepted: %v", e)
	}
	s.authorizer = &testAuthorizer{deny: true}
	in := &api.DeleteUserInput{}
	text(&in.BrokerId, v.ID)
	text(&in.Username, "initial")
	if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.deleteUser(tx.Context(), tx, in); return e }); e == nil {
		t.Fatal("denied mutation succeeded")
	}
	if storedBroker(t, s, v).Users[0].PendingChange != "" {
		t.Fatal("denied mutation persisted")
	}
}
func TestConfigurationDeletionProtectsPendingReference(t *testing.T) {
	s, ctx, v := controlFixture(t)
	c := ConfigurationRecord{Scope: v.Scope, ID: "c-owned", ARN: "arn:aws:mq:us-east-1:123456789012:configuration:c-owned", Name: "owned", Engine: v.Engine, EngineVersion: v.EngineVersion, AuthenticationStrategy: "SIMPLE", Tags: map[string]string{}, Revisions: []ConfigurationRevisionRecord{{Revision: 1, Data: DefaultConfiguration(v.Engine)}}}
	v.PendingConfiguration = ConfigurationReference{ID: c.ID, Revision: 1, Data: c.Revisions[0].Data}
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		if e := tx.PutConfiguration(c); e != nil {
			return e
		}
		return tx.PutBroker(v)
	}); e != nil {
		t.Fatal(e)
	}
	in := &api.DeleteConfigurationInput{}
	text(&in.ConfigurationId, c.ID)
	if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.deleteConfiguration(tx.Context(), tx, in); return e }); e == nil {
		t.Fatal("deleted pending configuration")
	}
	token := pageToken(ctx, "configurations", "last")
	other := awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: v.Partition, AccountID: v.AccountID, Region: "us-west-2"})
	if _, _, e := page(other, "configurations", nil, token); e == nil {
		t.Fatal("pagination cursor crossed region")
	}
	if _, _, e := page(ctx, "users:b-owned", nil, token); e == nil {
		t.Fatal("pagination cursor crossed operation")
	}
}

func TestRequestTagAuthorityAndRejectedEngineOperations(t *testing.T) {
	s, ctx, v := controlFixture(t)
	s.authorizer = &testAuthorizer{requestTag: true}
	if err := s.repository.Attempt(ctx, func(tx Transaction) error {
		resource, err := s.tagged(tx.Context(), tx, v.ARN, "CreateTags", map[string][]string{"aws:RequestTag/team": {"green"}, "aws:TagKeys": {"team"}})
		if err != nil {
			return err
		}
		resource.tags()["team"] = "green"
		return resource.put(tx)
	}); err != nil {
		t.Fatal(err)
	}
	if storedBroker(t, s, v).Tags["team"] != "green" {
		t.Fatal("authorized tag mutation missing")
	}
	if err := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.tagged(tx.Context(), tx, v.ARN, "CreateTags", map[string][]string{"aws:RequestTag/team": {"red"}})
		return err
	}); err == nil {
		t.Fatal("request-tag condition ignored")
	}
	s.authorizer = &testAuthorizer{}
	v.Engine = "RABBITMQ"
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutBroker(v) }); err != nil {
		t.Fatal(err)
	}
	input := &api.CreateUserInput{}
	text(&input.BrokerId, v.ID)
	text(&input.Username, "new-user")
	text(&input.Password, "new-password-123")
	if err := s.repository.Attempt(ctx, func(tx Transaction) error { _, err := s.createUser(tx.Context(), tx, input); return err }); err == nil {
		t.Fatal("RabbitMQ admitted an ActiveMQ-only user operation")
	}
	if len(storedBroker(t, s, v).Users) != 1 {
		t.Fatal("rejected user operation mutated users")
	}
}

type consoleRoleProvisioner struct{}

func (consoleRoleProvisioner) EnsureServiceLinkedRole(context.Context, string) error { return nil }

func TestCreateBrokerConsoleAccessByEngine(t *testing.T) {
	for _, tc := range []struct {
		name    string
		engine  string
		console bool
		groups  []string
	}{
		{name: "activemq-console", engine: "ACTIVEMQ", console: true, groups: []string{"clients"}},
		{name: "activemq-messaging-only", engine: "ACTIVEMQ"},
		{name: "rabbitmq-ignores-activemq-fields", engine: "RABBITMQ", console: true, groups: []string{"not an ActiveMQ group"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx, v := controlFixture(t)
			s.serviceLinkedRoles = consoleRoleProvisioner{}
			in := &api.CreateBrokerInput{}
			text(&in.BrokerName, "console-broker")
			text(&in.EngineType, tc.engine)
			text(&in.DeploymentMode, "SINGLE_INSTANCE")
			text(&in.HostInstanceType, "mq.t3.micro")
			boolean(&in.PubliclyAccessible, true)
			u := api.User{}
			text(&u.Username, "console-user")
			text(&u.Password, "console-password-123")
			boolean(&u.ConsoleAccess, tc.console)
			stringList(&u.Groups, tc.groups)
			in.Users = append(in.Users, u)
			if e := s.repository.Attempt(ctx, func(tx Transaction) error {
				out, e := s.createBroker(tx.Context(), tx, in)
				if e == nil {
					v.ID = value(out.BrokerId)
				}
				return e
			}); e != nil {
				t.Fatal(e)
			}
			created := storedBroker(t, s, v)
			user := created.Users[0]
			if user.Password != "console-password-123" || user.ConsoleAccess != (tc.engine == "ACTIVEMQ" && tc.console) {
				t.Fatalf("initial console authority not retained correctly: %+v", user)
			}
			if tc.engine == "RABBITMQ" && len(user.Groups) != 0 {
				t.Fatalf("RabbitMQ retained ActiveMQ groups: %+v", user)
			}
		})
	}
}

func TestConsoleUserCreationRetainsPendingAuthorityAcrossUpdates(t *testing.T) {
	s, ctx, v := controlFixture(t)
	create := &api.CreateUserInput{}
	text(&create.BrokerId, v.ID)
	text(&create.Username, "console-user")
	text(&create.Password, "console-password-123")
	boolean(&create.ConsoleAccess, true)
	if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.createUser(tx.Context(), tx, create); return e }); e != nil {
		t.Fatal(e)
	}
	update := &api.UpdateUserInput{}
	text(&update.BrokerId, v.ID)
	text(&update.Username, "console-user")
	text(&update.Password, "rotated-password-456")
	boolean(&update.ConsoleAccess, false)
	boolean(&update.ReplicationUser, true)
	if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.updateUser(tx.Context(), tx, update); return e }); e == nil {
		t.Fatal("console user admitted unsupported replication privilege")
	}
	update.ConsoleAccess, update.ReplicationUser = nil, nil
	if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.updateUser(tx.Context(), tx, update); return e }); e != nil {
		t.Fatal(e)
	}
	pending := storedBroker(t, s, v)
	u := pending.Users[findUser(pending.Users, "console-user")]
	if u.PendingChange != "CREATE" || u.Password != "" || u.ConsoleAccess || u.PendingPassword != "rotated-password-456" || !u.PendingConsoleAccess {
		t.Fatalf("pending creation lost console authority or activated early: %+v", u)
	}
	reboot := &api.RebootBrokerInput{}
	text(&reboot.BrokerId, v.ID)
	if e := s.repository.Attempt(ctx, func(tx Transaction) error { _, e := s.rebootBroker(tx.Context(), tx, reboot); return e }); e != nil {
		t.Fatal(e)
	}
	j := brokerJobs{s}
	job, _, e := j.Next(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Run(ctx, job); e != nil {
		t.Fatal(e)
	}
	done := storedBroker(t, s, v)
	u = done.Users[findUser(done.Users, "console-user")]
	if u.Password != "rotated-password-456" || !u.ConsoleAccess || u.PendingChange != "" || u.PendingPassword != "" || u.PendingConsoleAccess {
		t.Fatalf("reboot did not activate pending console user: %+v", u)
	}
}
