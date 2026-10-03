package lambda_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awstest"
	"stackd/internal/awswire"
	service "stackd/internal/services/lambda"
	"stackd/storage/lambda"
	"stackd/storage/sqlite"
	sqllambda "stackd/storage/sqlite/lambda"
)

func TestAliasOwnershipTransactionAndNativeRecreation(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		function := deployment()
		owned := lambda.AliasRecord{Key: lambda.FunctionReference{FunctionKey: function.Key, Qualifier: "live"}, FunctionVersion: 2, AdditionalVersion: 1, AdditionalWeight: 0.25, Description: "retained", Revision: "exact-revision", Owner: lambda.AliasOwner{StackID: "stack-a", LogicalID: "Alias", Token: "create-a"}}
		foreignFunction := function
		foreignFunction.Key.Region = "us-west-2"
		foreign := owned
		foreign.Key.FunctionKey, foreign.Owner = foreignFunction.Key, lambda.AliasOwner{}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(function); err != nil {
				return err
			}
			if err := tx.PutFunction(foreignFunction); err != nil {
				return err
			}
			if err := tx.PutAlias(owned); err != nil {
				return err
			}
			return tx.PutAlias(foreign)
		}); err != nil {
			t.Fatal(err)
		}
		abort := errors.New("abort owner replacement")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			replacement := owned
			replacement.Owner.Token, replacement.Revision = "replacement-token", "replacement-revision"
			if err := tx.PutAlias(replacement); err != nil {
				return err
			}
			if err := tx.DeleteAlias(foreign.Key); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatalf("ownership rollback: %v", err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			for _, want := range []lambda.AliasRecord{owned, foreign} {
				got, err := r.Alias(want.Key)
				if err != nil || got != want {
					t.Fatalf("rollback changed alias owner or crossed scope: %+v %v; want %+v", got, err, want)
				}
				rows, err := r.Aliases(want.Key.FunctionKey)
				if err != nil || len(rows) != 1 || rows[0] != want {
					t.Fatalf("scoped listing lost ownership: %+v %v; want %+v", rows, err, want)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteAlias(owned.Key); err != nil {
				return err
			}
			return tx.PutAlias(lambda.AliasRecord{Key: owned.Key, FunctionVersion: 1, Revision: "native-replacement"})
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			got, err := r.Alias(owned.Key)
			if err == nil && (got.Owner != (lambda.AliasOwner{}) || got.FunctionVersion != 1 || got.Revision != "native-replacement") {
				t.Fatalf("recreation retained former ownership: %+v", got)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func storedAliasCommand(t *testing.T, s *service.Service, ctx context.Context, name string, input any) (any, *awswire.Error) {
	t.Helper()
	model, _ := awscatalog.LookupService("lambda")
	op, ok := model.Operation(name)
	if !ok {
		t.Fatalf("unknown Lambda operation %q", name)
	}
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
}

func TestSQLiteAliasOwnerReopenRecoveryAndLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	function := deployment()
	owner := lambda.AliasOwner{StackID: "stack-a", LogicalID: "Alias", Token: "create-a"}
	want := lambda.AliasRecord{Key: lambda.FunctionReference{FunctionKey: function.Key, Qualifier: "live"}, FunctionVersion: 2, AdditionalVersion: 1, AdditionalWeight: 0.25, Description: "native retarget", Revision: "unchanged-revision-after-reopen", Owner: owner}
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutFunction(function); err != nil {
			return err
		}
		for _, version := range []uint64{1, 2} {
			function.Version = version
			if err := tx.PutFunctionVersion(function); err != nil {
				return err
			}
		}
		return tx.PutAlias(want)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo := sqllambda.New(db)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: function.Key.Partition, AccountID: function.Key.Account, Region: function.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: function.Key.Account})
	owned := service.WithAliasOwner(ctx, owner)
	s := service.New(service.Config{Repository: repo})
	t.Cleanup(func() { _ = s.Close() })
	create := &api.CreateAliasInput{FunctionName: new(api.FunctionName(function.Key.Name)), Name: new(api.Alias(want.Key.Qualifier)), FunctionVersion: new(api.VersionWithLatestPublished("1")), Description: new(api.Description("original request"))}
	out, wire := storedAliasCommand(t, s, owned, "CreateAlias", create)
	if wire != nil {
		t.Fatal(wire)
	}
	alias := out.(*api.CreateAliasOutput)
	if string(*alias.FunctionVersion) != "2" || string(*alias.RevisionId) != want.Revision || string(*alias.Description) != want.Description || alias.RoutingConfig == nil || alias.RoutingConfig.AdditionalVersionWeights["1"] != 0.25 {
		t.Fatalf("reopen recovery changed revision or routing: %+v", alias)
	}
	if err := repo.View(ctx, func(r lambda.Reader) error {
		got, err := r.Alias(want.Key)
		if err == nil && got != want {
			t.Fatalf("reopen recovery changed retained ownership: %+v", got)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Project the same alias onto the last schema before owner columns existed.
	// Reopening must preserve its old fields without adopting the old row.
	legacyPath := filepath.Join(t.TempDir(), "legacy.sqlite")
	historical := awstest.HistoricalSQLite(t, legacyPath, "../sqlite/schema", 297, path, nil)
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	legacyDB, err := sqlite.Open(t.Context(), legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacyDB.Close() })
	legacyRepo := sqllambda.New(legacyDB)
	legacyWant := want
	legacyWant.Owner = lambda.AliasOwner{}
	if err := legacyRepo.View(ctx, func(r lambda.Reader) error {
		got, err := r.Alias(want.Key)
		if err == nil && got != legacyWant {
			t.Fatalf("migration changed legacy alias or invented ownership: %+v", got)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	legacyService := service.New(service.Config{Repository: legacyRepo})
	t.Cleanup(func() { _ = legacyService.Close() })
	_, wire = storedAliasCommand(t, legacyService, owned, "CreateAlias", create)
	if wire == nil || wire.Code != "ResourceConflictException" {
		t.Fatalf("owner adopted a migrated native alias: %v", wire)
	}
	_, wire = storedAliasCommand(t, legacyService, owned, "DeleteAlias", &api.DeleteAliasInput{FunctionName: create.FunctionName, Name: create.Name})
	if wire == nil || wire.Code != "AccessDeniedException" {
		t.Fatalf("owner deleted a migrated native alias: %v", wire)
	}
	out, wire = storedAliasCommand(t, legacyService, ctx, "GetAlias", &api.GetAliasInput{FunctionName: create.FunctionName, Name: create.Name})
	if wire != nil || string(*out.(*api.GetAliasOutput).RevisionId) != want.Revision {
		t.Fatalf("ownership rejection changed legacy alias: %+v %v", out, wire)
	}
}
