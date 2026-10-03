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
}

func (r heldEnsure) Ensure(ctx context.Context, _ engine.Specification) (engine.Deployment, error) {
	close(r.entered)
	select {
	case <-ctx.Done():
		return engine.Deployment{}, ctx.Err()
	case <-r.release:
		return engine.Deployment{Endpoint: engine.Endpoint{Address: "127.0.0.1", Port: 6379}}, nil
	}
}
func TestOldNativeCompletionCannotReadyNewIncarnation(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	native := heldEnsure{entered: make(chan struct{}), release: make(chan struct{})}
	s := New(Config{Runtime: native, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	k := Key{Scope: Scope{"aws", "111111111111", "us-east-1"}, Kind: "cluster", Name: "owned"}
	v := Cluster{Key: k, RuntimeID: "old-incarnation", Status: "creating", Operation: "create", Shards: 1, ACLName: "open-access", ParameterGroup: "default.memorydb_valkey7", Version: 1, Due: now}
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
		if cluster.Status != "modifying" || cluster.Version != 2 {
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
