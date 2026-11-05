package athena

import (
	"context"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
)

func TestExecutionCatalogsCurrentIAMAndForeignScope(t *testing.T) {
	domain := memory.NewDomain()
	identities := iam.NewMemoryRepository(domain)
	identityService := iam.NewWithConfig(iam.Config{Repository: identities})
	repo := NewMemoryRepository(domain)
	service := New(Config{Repository: repo, Authorizer: authorization.New(identityService, nil)})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := Scope{"aws", "123456789012", "us-east-1"}
	root := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.AccountID})
	if err := repo.Update(root, func(tx Transaction) error {
		for _, row := range []CatalogRecord{
			{Key: ResourceKey{Scope: scope, Name: "lake"}, Data: api.DataCatalog{Name: new(api.CatalogNameString("lake")), Type: new(api.DataCatalogType("GLUE")), Parameters: api.ParametersMap{"catalog-id": "123456789012:s3tablescatalog/research"}}},
			{Key: ResourceKey{Scope: scope, Name: "denied"}, Data: api.DataCatalog{Name: new(api.CatalogNameString("denied")), Type: new(api.DataCatalogType("GLUE")), Parameters: api.ParametersMap{"catalog-id": "123456789012"}}},
			{Key: ResourceKey{Scope: Scope{"aws", "999999999999", "us-east-1"}, Name: "foreign-account"}, Data: api.DataCatalog{Name: new(api.CatalogNameString("foreign-account")), Type: new(api.DataCatalogType("GLUE"))}},
			{Key: ResourceKey{Scope: Scope{"aws", "123456789012", "us-west-2"}, Name: "foreign-region"}, Data: api.DataCatalog{Name: new(api.CatalogNameString("foreign-region")), Type: new(api.DataCatalogType("GLUE"))}},
		} {
			if err := tx.PutCatalog(row); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	user := iam.User{UserName: "catalog-reader", UserId: "AIDACATALOGREADER", Arn: "arn:aws:iam::123456789012:user/catalog-reader", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	caller := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: user.Arn, PrincipalID: user.UserId})
	setPolicy := func(document string) {
		t.Helper()
		user.IdentityPolicies.Inline["catalog"] = document
		if err := identities.Update(root, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: scope.Partition, AccountID: scope.AccountID}, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	setPolicy(`{"Statement":[{"Effect":"Allow","Action":"athena:GetDataCatalog","Resource":"arn:aws:athena:us-east-1:123456789012:datacatalog/lake"}]}`)
	discover := func() []api.DataCatalog {
		t.Helper()
		var rows []api.DataCatalog
		// Query jobs enlist storage before restoring the saved query caller.
		if err := repo.Update(context.Background(), func(tx Transaction) error {
			var err error
			queryCaller := awsctx.WithMetadata(tx.Context(), awsctx.FromContext(caller))
			rows, err = service.executionCatalogs(queryCaller, tx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	rows := discover()
	if len(rows) != 1 || value(rows[0].Name) != "lake" {
		t.Fatalf("unauthorized or foreign catalog exposed: %+v", rows)
	}
	id := "123456789012:s3tablescatalog/research"
	if err := service.authorizeExecutionCatalog(caller, "lake", id); err != nil {
		t.Fatal(err)
	}
	if err := service.authorizeExecutionCatalog(caller, "lake", "999999999999"); err == nil {
		t.Fatal("catalog id substitution admitted")
	}
	setPolicy(`{"Statement":[{"Effect":"Deny","Action":"athena:GetDataCatalog","Resource":"*"}]}`)
	if err := service.authorizeExecutionCatalog(caller, "lake", id); err == nil || wireError(err).Code != "AccessDeniedException" {
		t.Fatalf("stale IAM callback authority: %v", err)
	}
	if rows := discover(); len(rows) != 0 {
		t.Fatalf("denied catalog still exposed: %+v", rows)
	}
	setPolicy(`{"Statement":[{"Effect":"Allow","Action":"athena:GetDataCatalog","Resource":"*"}]}`)
	rows = discover()
	if len(rows) != 3 {
		t.Fatalf("saved query scope lost authorized registrations: %+v", rows)
	}
	wantIDs := map[string]string{"AwsDataCatalog": scope.AccountID, "lake": id, "denied": scope.AccountID}
	for _, row := range rows {
		name := value(row.Name)
		wantID, ok := wantIDs[name]
		if !ok || value(row.Type) != "GLUE" || string(row.Parameters["catalog-id"]) != wantID {
			t.Fatalf("authorized registration fields changed: %+v", row)
		}
		delete(wantIDs, name)
	}
	if len(wantIDs) != 0 {
		t.Fatalf("authorized registrations missing: %+v", wantIDs)
	}
	if err := service.authorizeExecutionCatalog(caller, "awsdatacatalog", scope.AccountID); err != nil {
		t.Fatalf("default catalog current callback authority: %v", err)
	}
	if err := repo.Update(root, func(tx Transaction) error {
		row, err := tx.Catalog(ResourceKey{Scope: scope, Name: "lake"})
		if err != nil {
			return err
		}
		row.Data.Parameters["catalog-id"] = "123456789012:replacement"
		return tx.PutCatalog(row)
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.authorizeExecutionCatalog(caller, "lake", id); err == nil {
		t.Fatal("changed registration retained callback authority")
	}
}
