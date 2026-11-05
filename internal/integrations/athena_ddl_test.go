package integrations

import (
	"context"
	"errors"
	"testing"

	native "stackd/engine/athena"
	athenaapi "stackd/internal/awsapi/athena"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/athena"
	"stackd/internal/services/glue"
)

func TestHiveDropDatabaseUsesAtomicRealCatalogSemantics(t *testing.T) {
	owner := glue.New(glue.Config{})
	defer owner.Close()
	metadata := awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}
	ctx := awsctx.WithMetadata(context.Background(), metadata)
	catalog := AthenaGlue{Glue: owner}
	engine := AthenaEngine{Glue: owner}
	request := athena.ExecutionRequest{Query: athena.QueryRecord{Key: athena.ResourceKey{Scope: athena.Scope{Partition: metadata.Partition, AccountID: metadata.AccountID, Region: metadata.Region}, Name: "drop-query"}, Caller: metadata}}
	call := func(action string, input any) {
		t.Helper()
		if _, rejected := catalog.command(ctx, action, input); rejected != nil {
			t.Fatalf("%s: %v", action, rejected)
		}
	}
	call("CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("nonempty"))}})
	call("CreateTable", &api.CreateTableInput{DatabaseName: new(api.NameString("nonempty")), TableInput: &api.TableInput{Name: new(api.NameString("actual_metadata")), PartitionKeys: api.ColumnList{{Name: new(api.NameString("region")), Type: new(api.ColumnTypeString("string"))}}, StorageDescriptor: &api.StorageDescriptor{Location: new(api.LocationString("s3://owned/actual-data/"))}}})
	call("CreatePartition", &api.CreatePartitionInput{DatabaseName: new(api.NameString("nonempty")), TableName: new(api.NameString("actual_metadata")), PartitionInput: &api.PartitionInput{Values: api.ValueStringList{"east"}}})
	call("CreateUserDefinedFunction", &api.CreateUserDefinedFunctionInput{DatabaseName: new(api.NameString("nonempty")), FunctionInput: &api.UserDefinedFunctionInput{FunctionName: new(api.NameString("owned_case")), ClassName: new(api.NameString("org.apache.hadoop.hive.ql.udf.generic.GenericUDFUpper")), OwnerName: new(api.NameString("owner")), OwnerType: new(api.PrincipalType("ROLE"))}})
	plan := native.HiveDDL{Kind: "DROP_DATABASE", Identifier: []string{"AwsDataCatalog", "nonempty"}}
	if err := engine.applyHiveDDL(ctx, request, plan); err == nil {
		t.Fatal("default RESTRICT deleted a non-empty database")
	}
	call("GetDatabase", &api.GetDatabaseInput{Name: new(api.NameString("nonempty"))})
	call("GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("nonempty")), Name: new(api.NameString("actual_metadata"))})
	call("GetPartition", &api.GetPartitionInput{DatabaseName: new(api.NameString("nonempty")), TableName: new(api.NameString("actual_metadata")), PartitionValues: api.ValueStringList{"east"}})
	plan.Cascade = true
	if err := engine.applyHiveDDL(ctx, request, plan); err != nil {
		t.Fatalf("CASCADE: %v", err)
	}
	for _, probe := range []struct {
		action string
		input  any
	}{
		{"GetDatabase", &api.GetDatabaseInput{Name: new(api.NameString("nonempty"))}},
		{"GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("nonempty")), Name: new(api.NameString("actual_metadata"))}},
		{"GetPartition", &api.GetPartitionInput{DatabaseName: new(api.NameString("nonempty")), TableName: new(api.NameString("actual_metadata")), PartitionValues: api.ValueStringList{"east"}}},
		{"GetUserDefinedFunction", &api.GetUserDefinedFunctionInput{DatabaseName: new(api.NameString("nonempty")), FunctionName: new(api.NameString("owned_case"))}},
	} {
		if _, rejected := catalog.command(ctx, probe.action, probe.input); rejected == nil || rejected.Code != "EntityNotFoundException" {
			t.Fatalf("%s survived metadata CASCADE: %v", probe.action, rejected)
		}
	}
	if err := engine.applyHiveDDL(ctx, request, plan); err == nil {
		t.Fatal("DROP without IF EXISTS accepted a missing database")
	}
	plan.IfExists = true
	if err := engine.applyHiveDDL(ctx, request, plan); err != nil {
		t.Fatalf("IF EXISTS did not accept a missing database: %v", err)
	}
	call("PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: new(api.PolicyJsonString(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"glue:DeleteDatabase","Resource":"*"}]}`))})
	var denied *awswire.Error
	if err := engine.applyHiveDDL(ctx, request, plan); !errors.As(err, &denied) || denied.Code != "AccessDeniedException" {
		t.Fatalf("IF EXISTS bypassed current resource-policy authority: %v", err)
	}
}

func TestPublicGlueDatabaseDeleteStillCascades(t *testing.T) {
	owner := glue.New(glue.Config{})
	defer owner.Close()
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	catalog := AthenaGlue{Glue: owner}
	for _, command := range []struct {
		action string
		input  any
	}{
		{"CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("public_delete"))}}},
		{"CreateTable", &api.CreateTableInput{DatabaseName: new(api.NameString("public_delete")), TableInput: &api.TableInput{Name: new(api.NameString("owned"))}}},
		{"DeleteDatabase", &api.DeleteDatabaseInput{Name: new(api.NameString("public_delete"))}},
	} {
		if _, rejected := catalog.command(ctx, command.action, command.input); rejected != nil {
			t.Fatalf("%s: %v", command.action, rejected)
		}
	}
	if _, rejected := catalog.command(ctx, "GetDatabase", &api.GetDatabaseInput{Name: new(api.NameString("public_delete"))}); rejected == nil || rejected.Code != "EntityNotFoundException" {
		t.Fatalf("public Glue delete stopped cascading: %v", rejected)
	}
}

func TestHiveCreateExternalTablePreservesDefaultRegistrationAuthority(t *testing.T) {
	owner := glue.New(glue.Config{})
	defer owner.Close()
	metadata := awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}
	ctx := awsctx.WithMetadata(context.Background(), metadata)
	catalog := AthenaGlue{Glue: owner}
	if _, rejected := catalog.command(ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("fixture"))}}); rejected != nil {
		t.Fatal(rejected)
	}
	registration := athenaapi.DataCatalog{Name: new(athenaapi.CatalogNameString("AwsDataCatalog")), Type: new(athenaapi.DataCatalogType("GLUE")), Parameters: athenaapi.ParametersMap{"catalog-id": athenaapi.ParametersMapValue(metadata.AccountID)}}
	request := athena.ExecutionRequest{
		Query:    athena.QueryRecord{Key: athena.ResourceKey{Scope: athena.Scope{Partition: metadata.Partition, AccountID: metadata.AccountID, Region: metadata.Region}, Name: "external-query"}, Caller: metadata},
		Catalog:  registration,
		Catalogs: []athenaapi.DataCatalog{registration},
	}
	revoked := false
	calls := 0
	denied := errors.New("current catalog authorization denied")
	request.AuthorizeCatalog = func(ctx context.Context, name, id string) error {
		calls++
		if name != "awsdatacatalog" || id != metadata.AccountID || awsctx.FromContext(ctx).PrincipalARN != metadata.PrincipalARN {
			t.Fatalf("Hive callback lost catalog or caller authority: name=%q id=%q caller=%+v", name, id, awsctx.FromContext(ctx))
		}
		if revoked {
			return denied
		}
		return nil
	}
	engine := AthenaEngine{Glue: owner}
	plan := native.HiveDDL{Kind: "CREATE_TABLE", Identifier: []string{"awsdatacatalog", "fixture", "events"}, External: true, Location: "s3://fixture-data/events/", Columns: []native.DDLColumn{{Name: "id", Type: "bigint"}}}
	if err := engine.applyHiveDDL(ctx, request, plan); err != nil {
		t.Fatalf("authorized default CREATE EXTERNAL TABLE: %v", err)
	}
	if _, rejected := catalog.command(ctx, "GetTable", &api.GetTableInput{CatalogId: new(api.CatalogIdString(metadata.AccountID)), DatabaseName: new(api.NameString("fixture")), Name: new(api.NameString("events"))}); rejected != nil {
		t.Fatalf("external table missing from admitted catalog: %v", rejected)
	}
	revoked = true
	plan.Identifier[2] = "revoked"
	if err := engine.applyHiveDDL(ctx, request, plan); !errors.Is(err, denied) {
		t.Fatalf("current catalog denial bypassed: %v", err)
	}
	if _, rejected := catalog.command(ctx, "GetTable", &api.GetTableInput{DatabaseName: new(api.NameString("fixture")), Name: new(api.NameString("revoked"))}); rejected == nil || rejected.Code != "EntityNotFoundException" {
		t.Fatalf("denied external table created: %v", rejected)
	}
	revoked = false
	request.Catalogs = []athenaapi.DataCatalog{}
	plan.Identifier[2] = "unregistered"
	if err := engine.applyHiveDDL(ctx, request, plan); err == nil {
		t.Fatal("selected registration bypassed the authoritative empty admitted list")
	}
	if calls != 2 {
		t.Fatalf("unexpected current authorization calls: %d", calls)
	}
}
