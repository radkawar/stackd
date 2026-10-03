package lambda_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awstest"
	service "stackd/internal/services/lambda"
	"stackd/storage/lambda"
	"stackd/storage/sqlite"
	sqljournal "stackd/storage/sqlite/journal"
	sqllambda "stackd/storage/sqlite/lambda"
)

func TestVersionOwnerScopedImmutableAndTransactional(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		latest := deployment()
		owner := lambda.VersionOwner{StackID: "stack-a", LogicalID: "Version", Token: "request-a"}
		other := lambda.VersionOwner{StackID: "stack-b", LogicalID: "Version", Token: "request-b"}
		keys := []lambda.FunctionKey{latest.Key, latest.Key, latest.Key, latest.Key, latest.Key}
		keys[1].Region, keys[2].Account, keys[3].Partition, keys[4].Name = "us-west-2", "222222222222", "aws-cn", "another-function"
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			for _, key := range keys {
				latest.Key = key
				if err := tx.PutFunction(latest); err != nil {
					return err
				}
				for version := uint64(1); version <= 2; version++ {
					published := latest
					published.Version, published.Revision = version, key.ARN()
					if _, err := tx.AllocateFunctionVersion(key); err != nil {
						return err
					}
					if err := tx.PutFunctionVersion(published); err != nil {
						return err
					}
				}
				if err := tx.PutFunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: key, Version: 1}, owner); err != nil {
					return err
				}
			}
			return tx.PutFunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: keys[0], Version: 1}, owner)
		}); err != nil {
			t.Fatal(err)
		}
		check := func() {
			t.Helper()
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				for _, key := range keys {
					got, err := r.OwnedFunctionVersion(key, owner)
					if err != nil || got.Key != key || got.Version != 1 || got.Revision != key.ARN() {
						t.Fatalf("scoped recovery = %+v %v", got, err)
					}
					got.Variables["ENV"] = "reader mutation"
					got, err = r.OwnedFunctionVersion(key, owner)
					if err != nil || got.Variables["ENV"] != "old" {
						t.Fatalf("receipt leaked immutable configuration: %+v %v", got, err)
					}
					receipt, err := r.FunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: key, Version: 1})
					if err != nil || receipt != owner {
						t.Fatalf("scoped receipt = %+v %v; want %+v", receipt, err, owner)
					}
					if _, err := r.FunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: key, Version: 2}); !errors.Is(err, lambda.ErrNotFound) {
						t.Fatalf("invented native ownership: %v", err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		check()
		for _, invalid := range []struct {
			version uint64
			owner   lambda.VersionOwner
		}{
			{2, owner}, {1, other}, {0, other}, {3, other}, {1, lambda.VersionOwner{}}, {1, lambda.VersionOwner{StackID: "stack-a", LogicalID: "Version"}},
		} {
			if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
				return tx.PutFunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: keys[0], Version: invalid.version}, invalid.owner)
			}); err == nil {
				t.Fatalf("accepted invalid/reassigned receipt: %+v", invalid)
			}
		}
		abort := errors.New("abort receipt deletion")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteFunctionVersion(lambda.FunctionVersionKey{FunctionKey: keys[0], Version: 1}); err != nil {
				return err
			}
			if err := tx.DeleteFunction(keys[1]); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal(err)
		}
		check()
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteFunctionVersion(lambda.FunctionVersionKey{FunctionKey: keys[0], Version: 1}); err != nil {
				return err
			}
			return tx.DeleteFunction(keys[1])
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			for _, key := range keys[:2] {
				if _, err := r.OwnedFunctionVersion(key, owner); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("deletion retained receipt: %v", err)
				}
				for _, version := range []uint64{1, 2} {
					if _, err := r.FunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: key, Version: version}); !errors.Is(err, lambda.ErrNotFound) {
						t.Fatalf("deletion retained owner: %v", err)
					}
				}
			}
			_, err := r.OwnedFunctionVersion(keys[2], owner)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func versionOwnerContext(t *testing.T, key lambda.FunctionKey) context.Context {
	t.Helper()
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.Account, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: key.Account})
}

func TestSQLiteVersionOwnerReopenRecoveryAndLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	latest := deployment()
	latest.State, latest.UpdateStatus, latest.DeploymentRevision = "Active", "Successful", "deployment-one"
	key := latest.Key
	owner := lambda.VersionOwner{StackID: "stack-a", LogicalID: "Version", Token: "request-a"}
	ctx := versionOwnerContext(t, key)
	owned := service.WithVersionOwner(ctx, owner)
	repo := sqllambda.New(db)
	if err := repo.Update(ctx, func(tx lambda.Transaction) error { return tx.PutFunction(latest) }); err != nil {
		t.Fatal(err)
	}
	s := service.New(service.Config{Repository: repo})
	in := &api.PublishVersionInput{FunctionName: new(api.FunctionName(key.Name)), Description: new(api.Description("immutable description")), RevisionId: new(api.String(latest.Revision)), CodeSha256: new(api.String(latest.CodeSHA256))}
	out, wire := storedAliasCommand(t, s, owned, "PublishVersion", in)
	if wire != nil {
		t.Fatal(wire)
	}
	want := out.(*api.PublishVersionOutput)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	latest.CodeSHA256, latest.Revision, latest.DeploymentRevision, latest.Description = "new-code", "new-revision", "deployment-two", "new description"
	latest.Variables["ENV"] = "new"
	if err := repo.Update(ctx, func(tx lambda.Transaction) error { return tx.PutFunction(latest) }); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo = sqllambda.New(db)
	s = service.New(service.Config{Repository: repo})
	t.Cleanup(func() { _ = s.Close() })
	out, wire = storedAliasCommand(t, s, owned, "PublishVersion", in)
	if wire != nil || !reflect.DeepEqual(out, want) {
		t.Fatalf("reopen retry published changed latest: %+v %v; want %+v", out, wire, want)
	}
	if err := repo.View(ctx, func(r lambda.Reader) error {
		got, err := r.OwnedFunctionVersion(key, owner)
		if err != nil || got.CodeSHA256 != "hash" || got.Variables["ENV"] != "old" || got.Description != "immutable description" || got.Revision != string(*want.RevisionId) {
			t.Fatalf("receipt lost immutable snapshot: %+v %v", got, err)
		}
		last, err := r.LastAllocatedVersion(key)
		if err != nil || last != 1 {
			t.Fatalf("retry advanced allocation: %d %v", last, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(t.TempDir(), "legacy.sqlite")
	historical := awstest.HistoricalSQLite(t, legacyPath, "../sqlite/schema", 298, path, nil)
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	legacyDB, err := sqlite.Open(t.Context(), legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacyDB.Close() })
	if err := sqllambda.New(legacyDB).View(ctx, func(r lambda.Reader) error {
		if _, err := r.OwnedFunctionVersion(key, owner); !errors.Is(err, lambda.ErrNotFound) {
			t.Fatalf("migration invented receipt: %v", err)
		}
		if _, err := r.FunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: key, Version: 1}); !errors.Is(err, lambda.ErrNotFound) {
			t.Fatalf("migration adopted native publication: %v", err)
		}
		got, err := r.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: key, Version: 1})
		if err != nil || got.Revision != string(*want.RevisionId) || got.CodeSHA256 != "hash" || got.Variables["ENV"] != "old" {
			t.Fatalf("migration changed publication: %+v %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVersionOwnerCollisionAndNativeDeletionPreserveAllocation(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		latest := deployment()
		latest.State, latest.UpdateStatus, latest.DeploymentRevision = "Active", "Successful", "deployment-one"
		ctx := versionOwnerContext(t, latest.Key)
		owner := lambda.VersionOwner{StackID: "stack-a", LogicalID: "Version", Token: "request-a"}
		other := lambda.VersionOwner{StackID: "stack-b", LogicalID: "Version", Token: "request-b"}
		if err := repo.Update(ctx, func(tx lambda.Transaction) error { return tx.PutFunction(latest) }); err != nil {
			t.Fatal(err)
		}
		s := service.New(service.Config{Repository: repo})
		t.Cleanup(func() { _ = s.Close() })
		in := &api.PublishVersionInput{FunctionName: new(api.FunctionName(latest.Key.Name))}
		publish := func(callCtx context.Context, want string) *api.PublishVersionOutput {
			t.Helper()
			out, wire := storedAliasCommand(t, s, callCtx, "PublishVersion", in)
			if wire != nil {
				t.Fatal(wire)
			}
			got := out.(*api.PublishVersionOutput)
			if string(*got.Version) != want {
				t.Fatalf("publication version = %s; want %s", *got.Version, want)
			}
			return got
		}
		first := publish(service.WithVersionOwner(ctx, owner), "1")
		if got := publish(ctx, "1"); !reflect.DeepEqual(got, first) {
			t.Fatalf("unchanged native publication changed snapshot: %+v; want %+v", got, first)
		}
		_, wire := storedAliasCommand(t, s, service.WithVersionOwner(ctx, other), "PublishVersion", in)
		if wire == nil || wire.Code != "ResourceConflictException" {
			t.Fatalf("foreign owner adopted unchanged publication: %v", wire)
		}
		if err := repo.View(ctx, func(r lambda.Reader) error {
			receipt, err := r.FunctionVersionOwner(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1})
			if err != nil || receipt != owner {
				t.Fatalf("collision changed ownership: %+v %v", receipt, err)
			}
			if _, err := r.OwnedFunctionVersion(latest.Key, other); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("collision retained foreign receipt: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, wire := storedAliasCommand(t, s, ctx, "DeleteFunction", &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(latest.Key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("1"))}); wire != nil {
			t.Fatal(wire)
		}
		publish(ctx, "2")
		_, wire = storedAliasCommand(t, s, service.WithVersionOwner(ctx, owner), "DeleteFunction", &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(latest.Key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("2"))})
		if wire == nil || wire.Code != "AccessDeniedException" {
			t.Fatalf("old receipt deleted native successor: %v", wire)
		}
		if _, wire := storedAliasCommand(t, s, ctx, "DeleteFunction", &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(latest.Key.Name))}); wire != nil {
			t.Fatal(wire)
		}
		if err := repo.Update(ctx, func(tx lambda.Transaction) error { return tx.PutFunction(latest) }); err != nil {
			t.Fatal(err)
		}
		publish(ctx, "3")
		_, wire = storedAliasCommand(t, s, service.WithVersionOwner(ctx, owner), "PublishVersion", in)
		if wire == nil || wire.Code != "ResourceConflictException" {
			t.Fatalf("owner adopted native recreation: %v", wire)
		}
		if err := repo.View(ctx, func(r lambda.Reader) error {
			for _, receipt := range []lambda.VersionOwner{owner, other} {
				if _, err := r.OwnedFunctionVersion(latest.Key, receipt); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatalf("full-name recreation retained receipt: %v", err)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSQLiteVersionReceiptAndJournalCommitTogether(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "receipt-events.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo, events := sqllambda.New(db), sqljournal.New(db)
	latest := deployment()
	latest.State, latest.UpdateStatus, latest.DeploymentRevision = "Active", "Successful", "deployment-one"
	ctx := versionOwnerContext(t, latest.Key)
	owner := lambda.VersionOwner{StackID: "private-stack-identity", LogicalID: "private-logical-identity", Token: "private-receipt-token"}
	owned := service.WithVersionOwner(ctx, owner)
	if err := repo.Update(ctx, func(tx lambda.Transaction) error { return tx.PutFunction(latest) }); err != nil {
		t.Fatal(err)
	}
	s := service.New(service.Config{Repository: repo, APIEvents: apievents.New(events)})
	t.Cleanup(func() { _ = s.Close() })
	in := &api.PublishVersionInput{FunctionName: new(api.FunctionName(latest.Key.Name))}
	abort := errors.New("abort publication")
	if err := repo.Update(owned, func(tx lambda.Transaction) error {
		if _, wire := storedAliasCommand(t, s, tx.Context(), "PublishVersion", in); wire != nil {
			return wire
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if err := repo.View(ctx, func(r lambda.Reader) error {
		if _, err := r.OwnedFunctionVersion(latest.Key, owner); !errors.Is(err, lambda.ErrNotFound) {
			t.Fatalf("rollback retained receipt: %v", err)
		}
		if _, err := r.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1}); !errors.Is(err, lambda.ErrNotFound) {
			t.Fatalf("rollback retained publication: %v", err)
		}
		last, err := r.LastAllocatedVersion(latest.Key)
		if err != nil || last != 0 {
			t.Fatalf("rollback advanced allocation: %d %v", last, err)
		}
		got, err := r.Function(latest.Key)
		if err != nil || got.Revision != latest.Revision {
			t.Fatalf("rollback changed latest revision: %+v %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if committed, err := events.Read(ctx, 0, 10); err != nil || len(committed) != 0 {
		t.Fatalf("rollback committed an API event: %+v %v", committed, err)
	}
	if _, wire := storedAliasCommand(t, s, owned, "PublishVersion", in); wire != nil {
		t.Fatal(wire)
	}
	if err := repo.View(ctx, func(r lambda.Reader) error {
		v, err := r.OwnedFunctionVersion(latest.Key, owner)
		if err != nil || v.Version != 1 || v.CodeSHA256 != latest.CodeSHA256 {
			t.Fatalf("commit lost publication receipt: %+v %v", v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	committed, err := events.Read(ctx, 0, 10)
	if err != nil || len(committed) != 1 || committed[0].APICallCompleted == nil || committed[0].APICallCompleted.ErrorCode != "" {
		t.Fatalf("commit lost API event: %+v %v", committed, err)
	}
	call := committed[0].APICallCompleted
	for _, private := range []string{owner.StackID, owner.LogicalID, owner.Token} {
		if strings.Contains(string(call.RequestParameters), private) || strings.Contains(string(call.ResponseElements), private) {
			t.Fatal("publication leaked private owner identity onto the wire")
		}
	}
}
