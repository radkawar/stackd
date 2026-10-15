package integrations

import (
	"context"
	"errors"
	"testing"

	native "stackd/engine/athena"
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
