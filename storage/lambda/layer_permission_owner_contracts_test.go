package lambda_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awstest"
	"stackd/internal/awswire"
	service "stackd/internal/services/lambda"
	"stackd/journal"
	"stackd/storage/lambda"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqljournal "stackd/storage/sqlite/journal"
	sqllambda "stackd/storage/sqlite/lambda"
)

func permissionOwnerKey() lambda.LayerPermissionKey {
	return lambda.LayerPermissionKey{LayerVersionKey: lambda.LayerVersionKey{LayerKey: lambda.LayerKey{Scope: deployment().Key.Scope, Name: "permission-layer"}, Version: 1}, StatementID: "owned-statement"}
}

func seedPermissionLayer(t *testing.T, repo lambda.Repository, key lambda.LayerVersionKey) {
	t.Helper()
	if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
		return tx.PutLayerVersion(lambda.LayerVersionRecord{Key: key, Created: deployment().Modified})
	}); err != nil {
		t.Fatal(err)
	}
}

func permissionOwnerInput(key lambda.LayerPermissionKey) *api.AddLayerVersionPermissionInput {
	return &api.AddLayerVersionPermissionInput{LayerName: new(api.LayerName(key.Name)), VersionNumber: new(api.LayerVersionNumber(key.Version)), StatementId: new(api.StatementId(key.StatementID)), Action: new(api.LayerPermissionAllowedAction("lambda:GetLayerVersion")), Principal: new(api.LayerPermissionAllowedPrincipal("*"))}
}

func permissionOwnerDelete(key lambda.LayerPermissionKey) *api.RemoveLayerVersionPermissionInput {
	return &api.RemoveLayerVersionPermissionInput{LayerName: new(api.LayerName(key.Name)), VersionNumber: new(api.LayerVersionNumber(key.Version)), StatementId: new(api.StatementId(key.StatementID))}
}

func permissionOwnerAdd(t *testing.T, s *service.Service, ctx context.Context, in *api.AddLayerVersionPermissionInput) *api.AddLayerVersionPermissionOutput {
	t.Helper()
	out, wire := storedAliasCommand(t, s, ctx, "AddLayerVersionPermission", in)
	if wire != nil {
		t.Fatal(wire)
	}
	return out.(*api.AddLayerVersionPermissionOutput)
}

func assertLayerPermissionRecovery(t *testing.T, got, wanted *api.AddLayerVersionPermissionOutput) {
	t.Helper()
	var actual, expected map[string]any
	if err := json.Unmarshal([]byte(*got.Statement), &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(*wanted.Statement), &expected); err != nil {
		t.Fatal(err)
	}
	if *got.RevisionId != *wanted.RevisionId || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("recovery changed statement/revision: %v (%s), want %v (%s)", actual, *got.RevisionId, expected, *wanted.RevisionId)
	}
}

func requirePermissionCode(t *testing.T, wire *awswire.Error, code string) {
	t.Helper()
	if wire == nil || wire.Code != code {
		t.Fatalf("error = %v, want %s", wire, code)
	}
}

func TestLayerPermissionOwnerScopedReceiptsAndCleanup(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		base := permissionOwnerKey()
		owner := lambda.LayerPermissionOwner{StackID: "stack", LogicalID: "Permission", Token: "token"}
		keys := []lambda.LayerPermissionKey{base, base, base, base, base, base, base}
		keys[1].Partition, keys[2].Account, keys[3].Region, keys[4].Name, keys[5].Version, keys[6].StatementID = "aws-cn", "222222222222", "us-west-2", "other-layer", 2, "sibling"
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			for i, key := range keys {
				if i != 6 {
					if err := tx.PutLayerVersion(lambda.LayerVersionRecord{Key: key.LayerVersionKey, Created: deployment().Modified}); err != nil {
						return err
					}
					if err := tx.PutLayerPolicy(lambda.LayerPolicy{Key: key.LayerVersionKey, Document: `{"Version":"2012-10-17","Statement":[]}`, Revision: "before"}); err != nil {
						return err
					}
				}
				v := owner
				v.Token = key.LayerVersionKey.ARN() + "/" + key.StatementID
				if err := tx.PutLayerPermissionOwner(key, v); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		check := func() {
			t.Helper()
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				for _, key := range keys {
					got, err := r.LayerPermissionOwner(key)
					if err != nil || got.StackID != owner.StackID || got.LogicalID != owner.LogicalID || got.Token != key.LayerVersionKey.ARN()+"/"+key.StatementID {
						t.Fatalf("scoped receipt = %+v %v for %+v", got, err, key)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		check()
		for _, invalid := range []lambda.LayerPermissionOwner{{}, {StackID: "stack", LogicalID: "Permission"}, owner} {
			if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutLayerPermissionOwner(base, invalid) }); err == nil {
				t.Fatalf("accepted incomplete or replacement receipt: %+v", invalid)
			}
		}
		abort := errors.New("rollback permission receipts")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteLayerPolicy(base.LayerVersionKey); err != nil {
				return err
			}
			if err := tx.DeleteLayerVersion(keys[1].LayerVersionKey); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal(err)
		}
		check()
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutLayerPolicy(lambda.LayerPolicy{Key: base.LayerVersionKey, Document: `{"Version":"2012-10-17","Statement":[]}`, Revision: "after"}); err != nil {
				return err
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		check()
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteLayerPolicy(base.LayerVersionKey); err != nil {
				return err
			}
			return tx.DeleteLayerVersion(keys[1].LayerVersionKey)
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			for _, key := range []lambda.LayerPermissionKey{base, keys[1], keys[6]} {
				if _, err := r.LayerPermissionOwner(key); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("deleted policy/layer retained receipt: %+v %v", key, err)
				}
			}
			for _, key := range keys[2:6] {
				if _, err := r.LayerPermissionOwner(key); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLayerPermissionOwnerRecoveryReplacementAndNativeOrdering(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		key := permissionOwnerKey()
		seedPermissionLayer(t, repo, key.LayerVersionKey)
		ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
		owner := lambda.LayerPermissionOwner{StackID: "private-stack", LogicalID: "private-logical", Token: "private-token"}
		owned := service.WithLayerPermissionOwner(ctx, owner)
		s := service.New(service.Config{Repository: repo})
		t.Cleanup(func() { _ = s.Close() })
		in, deletion := permissionOwnerInput(key), permissionOwnerDelete(key)
		first := permissionOwnerAdd(t, s, owned, in)
		in.RevisionId = new(api.String("stale"))
		recovered := permissionOwnerAdd(t, s, owned, in)
		assertLayerPermissionRecovery(t, recovered, first)
		_, wire := storedAliasCommand(t, s, ctx, "AddLayerVersionPermission", in)
		requirePermissionCode(t, wire, "ResourceConflictException")
		deletion.RevisionId = new(api.String("stale"))
		_, wire = storedAliasCommand(t, s, ctx, "RemoveLayerVersionPermission", deletion)
		requirePermissionCode(t, wire, "PreconditionFailedException")
		deletion.RevisionId, in.RevisionId = nil, nil
		for _, bad := range []lambda.LayerPermissionOwner{{}, {StackID: owner.StackID}, {StackID: "foreign", LogicalID: owner.LogicalID, Token: owner.Token}, {StackID: owner.StackID, LogicalID: "foreign", Token: owner.Token}, {StackID: owner.StackID, LogicalID: owner.LogicalID, Token: "foreign"}} {
			_, wire := storedAliasCommand(t, s, service.WithLayerPermissionOwner(ctx, bad), "AddLayerVersionPermission", in)
			requirePermissionCode(t, wire, "AccessDeniedException")
		}
		sibling := key
		sibling.StatementID = "sibling"
		permissionOwnerAdd(t, s, owned, permissionOwnerInput(sibling))
		if _, wire := storedAliasCommand(t, s, ctx, "RemoveLayerVersionPermission", deletion); wire != nil {
			t.Fatal(wire)
		}
		if err := repo.View(ctx, func(r lambda.Reader) error {
			if _, err := r.LayerPermissionOwner(key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("native deletion retained receipt: %v", err)
			}
			got, err := r.LayerPermissionOwner(sibling)
			if err != nil || got != owner {
				t.Fatalf("sibling receipt changed: %+v %v", got, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		permissionOwnerAdd(t, s, ctx, in)
		_, wire = storedAliasCommand(t, s, owned, "AddLayerVersionPermission", in)
		requirePermissionCode(t, wire, "AccessDeniedException")
		if _, wire := storedAliasCommand(t, s, owned, "RemoveLayerVersionPermission", deletion); wire != nil {
			t.Fatal(wire)
		}
		_, wire = storedAliasCommand(t, s, owned, "RemoveLayerVersionPermission", deletion)
		requirePermissionCode(t, wire, "ResourceNotFoundException")
		if _, wire := storedAliasCommand(t, s, owned, "RemoveLayerVersionPermission", permissionOwnerDelete(sibling)); wire != nil {
			t.Fatal(wire)
		}
		if err := repo.View(ctx, func(r lambda.Reader) error {
			if _, err := r.LayerPolicy(key.LayerVersionKey); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("last removal retained policy: %v", err)
			}
			if _, err := r.LayerPermissionOwner(sibling); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("last removal retained receipt: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(ctx, func(tx lambda.Transaction) error { return tx.DeleteLayerVersion(key.LayerVersionKey) }); err != nil {
			t.Fatal(err)
		}
		_, wire = storedAliasCommand(t, s, owned, "RemoveLayerVersionPermission", deletion)
		requirePermissionCode(t, wire, "ResourceNotFoundException")
		_, wire = storedAliasCommand(t, s, ctx, "RemoveLayerVersionPermission", deletion)
		requirePermissionCode(t, wire, "ResourceNotFoundException")
	})
}

func TestLayerPermissionOwnerCurrentIAMAndConcurrentRecovery(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		key := permissionOwnerKey()
		seedPermissionLayer(t, repo, key.LayerVersionKey)
		ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
		metadata := awsctx.FromContext(ctx)
		metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::111111111111:user/operator", "AIDA11111111111111111"
		ctx = awsctx.WithMetadata(ctx, metadata)
		owner := lambda.LayerPermissionOwner{StackID: "stack", LogicalID: "Permission", Token: "token"}
		owned := service.WithLayerPermissionOwner(ctx, owner)
		identity := &layerOwnerPolicies{}
		identity.allow.Store(true)
		s := service.New(service.Config{Repository: repo, Authorizer: authorization.New(identity, nil)})
		t.Cleanup(func() { _ = s.Close() })
		in, deletion := permissionOwnerInput(key), permissionOwnerDelete(key)
		type result struct {
			output any
			wire   *awswire.Error
		}
		results, start := make(chan result, 2), make(chan struct{})
		for range 2 {
			go func() {
				<-start
				out, wire := storedAliasCommand(t, s, owned, "AddLayerVersionPermission", in)
				results <- result{out, wire}
			}()
		}
		close(start)
		a, b := <-results, <-results
		if a.wire != nil || b.wire != nil {
			t.Fatalf("concurrent exact retry diverged: %+v %+v", a, b)
		}
		assertLayerPermissionRecovery(t, a.output.(*api.AddLayerVersionPermissionOutput), b.output.(*api.AddLayerVersionPermissionOutput))
		identity.allow.Store(false)
		for _, op := range []struct {
			name  string
			input any
		}{{"AddLayerVersionPermission", in}, {"RemoveLayerVersionPermission", deletion}} {
			_, wire := storedAliasCommand(t, s, owned, op.name, op.input)
			requirePermissionCode(t, wire, "AccessDeniedException")
		}
		identity.allow.Store(true)
		assertLayerPermissionRecovery(t, permissionOwnerAdd(t, s, owned, in), a.output.(*api.AddLayerVersionPermissionOutput))
		if _, wire := storedAliasCommand(t, s, owned, "RemoveLayerVersionPermission", deletion); wire != nil {
			t.Fatal(wire)
		}
		identity.allow.Store(false)
		_, wire := storedAliasCommand(t, s, owned, "RemoveLayerVersionPermission", deletion)
		requirePermissionCode(t, wire, "AccessDeniedException")
	})
}

func TestSQLiteLayerPermissionOwnerReopenAndLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := permissionOwnerKey()
	repo := sqllambda.New(db)
	seedPermissionLayer(t, repo, key.LayerVersionKey)
	ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
	owner := lambda.LayerPermissionOwner{StackID: "stack", LogicalID: "Permission", Token: "token"}
	owned := service.WithLayerPermissionOwner(ctx, owner)
	s := service.New(service.Config{Repository: repo})
	in := permissionOwnerInput(key)
	first := permissionOwnerAdd(t, s, owned, in)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	s = service.New(service.Config{Repository: sqllambda.New(db)})
	t.Cleanup(func() { _ = s.Close() })
	assertLayerPermissionRecovery(t, permissionOwnerAdd(t, s, owned, in), first)
	legacyPath := filepath.Join(t.TempDir(), "legacy.sqlite")
	historical := awstest.HistoricalSQLite(t, legacyPath, "../sqlite/schema", 300, path, nil)
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	legacyDB, err := sqlite.Open(t.Context(), legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacyDB.Close() })
	legacyRepo := sqllambda.New(legacyDB)
	legacy := service.New(service.Config{Repository: legacyRepo})
	t.Cleanup(func() { _ = legacy.Close() })
	if err := legacyRepo.View(ctx, func(r lambda.Reader) error {
		if _, err := r.LayerPermissionOwner(key); !errors.Is(err, lambda.ErrNotFound) {
			t.Fatalf("migration invented receipt: %v", err)
		}
		policy, err := r.LayerPolicy(key.LayerVersionKey)
		if err != nil || policy.Revision != string(*first.RevisionId) {
			t.Fatalf("migration changed native policy: %+v %v", policy, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, wire := storedAliasCommand(t, legacy, owned, "AddLayerVersionPermission", in)
	requirePermissionCode(t, wire, "AccessDeniedException")
}

func TestLayerPermissionOwnerPolicyReceiptAndEventRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repo lambda.Repository
			var events journal.Storage
			if backend == "memory" {
				domain := memory.NewDomain()
				repo, events = lambda.NewMemory(domain), journal.NewMemory(domain)
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "events.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo, events = sqllambda.New(db), sqljournal.New(db)
			}
			key := permissionOwnerKey()
			seedPermissionLayer(t, repo, key.LayerVersionKey)
			ctx := versionOwnerContext(t, lambda.FunctionKey{Scope: key.Scope})
			owner := lambda.LayerPermissionOwner{StackID: "private-stack", LogicalID: "private-logical", Token: "private-token"}
			owned := service.WithLayerPermissionOwner(ctx, owner)
			s := service.New(service.Config{Repository: repo, APIEvents: apievents.New(events)})
			t.Cleanup(func() { _ = s.Close() })
			in, deletion := permissionOwnerInput(key), permissionOwnerDelete(key)
			abort := errors.New("rollback permission mutation")
			if err := repo.Update(owned, func(tx lambda.Transaction) error {
				if _, wire := storedAliasCommand(t, s, tx.Context(), "AddLayerVersionPermission", in); wire != nil {
					return wire
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			if err := repo.View(ctx, func(r lambda.Reader) error {
				if _, err := r.LayerPolicy(key.LayerVersionKey); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("aborted Add retained policy: %v", err)
				}
				if _, err := r.LayerPermissionOwner(key); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("aborted Add retained receipt: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if rows, err := events.Read(ctx, 0, 10); err != nil || len(rows) != 0 {
				t.Fatalf("aborted Add retained event: %+v %v", rows, err)
			}
			first := permissionOwnerAdd(t, s, owned, in)
			if err := repo.Update(owned, func(tx lambda.Transaction) error {
				if _, wire := storedAliasCommand(t, s, tx.Context(), "RemoveLayerVersionPermission", deletion); wire != nil {
					return wire
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatal(err)
			}
			if err := repo.View(ctx, func(r lambda.Reader) error {
				got, err := r.LayerPermissionOwner(key)
				if err != nil || got != owner {
					t.Fatalf("aborted Remove changed receipt: %+v %v", got, err)
				}
				policy, err := r.LayerPolicy(key.LayerVersionKey)
				if err != nil || policy.Revision != string(*first.RevisionId) {
					t.Fatalf("aborted Remove changed policy: %+v %v", policy, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			rows, err := events.Read(ctx, 0, 10)
			if err != nil || len(rows) != 1 || rows[0].APICallCompleted == nil || rows[0].APICallCompleted.EventName != "AddLayerVersionPermission20181031" {
				t.Fatalf("policy and event diverged: %+v %v", rows, err)
			}
			encoded, err := json.Marshal(rows[0].APICallCompleted)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{owner.StackID, owner.LogicalID, owner.Token} {
				if strings.Contains(string(encoded), private) {
					t.Fatal("API event leaked private receipt")
				}
			}
			if _, wire := storedAliasCommand(t, s, owned, "RemoveLayerVersionPermission", deletion); wire != nil {
				t.Fatal(wire)
			}
			rows, err = events.Read(ctx, 0, 10)
			if err != nil || len(rows) != 2 || rows[1].APICallCompleted == nil || rows[1].APICallCompleted.EventName != "RemoveLayerVersionPermission20181031" {
				t.Fatalf("committed Remove lost event: %+v %v", rows, err)
			}
		})
	}
}
