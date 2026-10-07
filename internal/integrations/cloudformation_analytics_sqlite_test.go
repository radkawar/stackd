package integrations

import (
	"path/filepath"
	"stackd/internal/awscommands"
	"stackd/internal/services/athena"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/glue"
	"stackd/storage/sqlite"
	athenasqlite "stackd/storage/sqlite/athena"
	gluesqlite "stackd/storage/sqlite/glue"
	"testing"
)

func TestAnalyticsIncarnationsSurviveNativeRepositoryReopen(t *testing.T) {
	ctx := cfnAnalyticsTestContext()
	path := filepath.Join(t.TempDir(), "analytics.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	glueService := glue.New(glue.Config{Repository: gluesqlite.New(db)})
	athenaService := athena.New(athena.Config{Repository: athenasqlite.New(db)})
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"glue": glueService, "athena": athenaService})
	handlers := CloudFormationAnalyticsHandlers(commands)
	resources := []cloudformation.ResourceRequest{
		cfnAnalyticsTestRequest("AWS::Glue::Database", cloudformation.Properties{"CatalogId": "123456789012", "DatabaseInput": map[string]any{"Name": "analytics_db"}}),
		cfnAnalyticsTestRequest("AWS::Glue::Table", cloudformation.Properties{"CatalogId": "123456789012", "DatabaseName": "analytics_db", "TableInput": map[string]any{"Name": "facts", "PartitionKeys": []any{map[string]any{"Name": "day", "Type": "string"}}}}),
		cfnAnalyticsTestRequest("AWS::Glue::Partition", cloudformation.Properties{"CatalogId": "123456789012", "DatabaseName": "analytics_db", "TableName": "facts", "PartitionInput": map[string]any{"Values": []any{"2026-10-06"}}}),
		cfnAnalyticsTestRequest("AWS::Glue::Classifier", cloudformation.Properties{"JsonClassifier": map[string]any{"Name": "facts-json", "JsonPath": "$"}}),
		cfnAnalyticsTestRequest("AWS::Glue::SecurityConfiguration", cloudformation.Properties{"Name": "analytics-security", "EncryptionConfiguration": map[string]any{"S3Encryptions": []any{map[string]any{"S3EncryptionMode": "SSE-S3"}}}}),
		cfnAnalyticsTestRequest("AWS::Glue::Registry", cloudformation.Properties{"Name": "analytics-registry"}),
		cfnAnalyticsTestRequest("AWS::Glue::Schema", cloudformation.Properties{"Name": "Fact", "Registry": map[string]any{"Name": "analytics-registry"}, "DataFormat": "AVRO", "Compatibility": "NONE", "SchemaDefinition": `{"type":"record","name":"Fact","fields":[{"name":"id","type":"int"}]}`}),
		cfnAnalyticsTestRequest("AWS::Glue::SchemaVersion", cloudformation.Properties{"Schema": map[string]any{"SchemaName": "Fact", "RegistryName": "analytics-registry"}, "SchemaDefinition": `{"type":"record","name":"Fact","fields":[{"name":"id","type":"long"}]}`}),
		cfnAnalyticsTestRequest("AWS::Athena::WorkGroup", cloudformation.Properties{"Name": "native-analytics"}),
		cfnAnalyticsTestRequest("AWS::Athena::NamedQuery", cloudformation.Properties{"Name": "saved", "Database": "analytics_db", "QueryString": "SELECT 1", "WorkGroup": "native-analytics"}),
		cfnAnalyticsTestRequest("AWS::Athena::PreparedStatement", cloudformation.Properties{"StatementName": "lookup", "WorkGroup": "native-analytics", "QueryStatement": "SELECT ?"}),
		cfnAnalyticsTestRequest("AWS::Glue::DataCatalogEncryptionSettings", cloudformation.Properties{"CatalogId": "123456789012", "DataCatalogEncryptionSettings": map[string]any{"ConnectionPasswordEncryption": map[string]any{"ReturnConnectionPasswordEncrypted": false, "KmsKeyId": "configured-customer-key"}}}),
		cfnAnalyticsTestRequest("AWS::Glue::Catalog", cloudformation.Properties{"Name": "analytics-catalog"}),
		cfnAnalyticsTestRequest("AWS::Glue::Connection", cloudformation.Properties{"CatalogId": "123456789012", "ConnectionInput": map[string]any{"Name": "analytics-jdbc", "ConnectionType": "JDBC", "ConnectionProperties": map[string]any{"JDBC_CONNECTION_URL": "jdbc:postgresql://localhost/catalog", "USERNAME": "reader", "PASSWORD": "reopened-secret"}}}),
		cfnAnalyticsTestRequest("AWS::Glue::Job", cloudformation.Properties{"Name": "analytics-job", "Role": "arn:aws:iam::123456789012:role/job", "Command": map[string]any{"Name": "pythonshell", "PythonVersion": "3", "ScriptLocation": "s3://owned/job.py"}, "MaxCapacity": 0.0625}),
		cfnAnalyticsTestRequest("AWS::Glue::Workflow", cloudformation.Properties{"Name": "analytics-workflow"}),
		cfnAnalyticsTestRequest("AWS::Glue::Trigger", cloudformation.Properties{"Name": "analytics-trigger", "Type": "ON_DEMAND", "WorkflowName": "analytics-workflow", "Actions": []any{map[string]any{"JobName": "analytics-job"}}}),
		cfnAnalyticsTestRequest("AWS::Athena::DataCatalog", cloudformation.Properties{"Name": "analytics-glue", "Type": "GLUE", "Parameters": map[string]any{"catalog-id": "123456789012"}}),
	}
	for i := range resources {
		resources[i].LogicalID = resources[i].Type
		result, err := handlers[resources[i].Type].Create(ctx, resources[i])
		if err != nil {
			t.Fatalf("create %s: %v", resources[i].Type, err)
		}
		resources[i].PhysicalID = result.PhysicalID
	}
	// Slash-separated pairs are valid AWS metadata and exercise private key/value boundaries.
	metadata := cfnAnalyticsTestRequest("AWS::Glue::SchemaVersionMetadata", cloudformation.Properties{"SchemaVersionId": resources[7].PhysicalID, "Key": "purpose/analytics/category/", "Value": "query/lookup"})
	metadata.LogicalID = "VersionMetadata"
	result, err := handlers[metadata.Type].Create(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.PhysicalID = result.PhysicalID
	resources = append(resources, metadata)
	boundary := cfnAnalyticsTestRequest(metadata.Type, cloudformation.Properties{"SchemaVersionId": resources[7].PhysicalID, "Key": "purpose/analytics/", "Value": "category/query/lookup"})
	boundary.LogicalID = "VersionMetadataBoundary"
	result, err = handlers[boundary.Type].Create(ctx, boundary)
	if err != nil {
		t.Fatal(err)
	}
	boundary.PhysicalID = result.PhysicalID
	resources = append(resources, boundary)
	_ = glueService.Close()
	_ = athenaService.Close()
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	glueService = glue.New(glue.Config{Repository: gluesqlite.New(db)})
	athenaService = athena.New(athena.Config{Repository: athenasqlite.New(db)})
	t.Cleanup(func() { _ = glueService.Close(); _ = athenaService.Close(); _ = db.Close() })
	commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"glue": glueService, "athena": athenaService})
	handlers = CloudFormationAnalyticsHandlers(commands)
	for _, r := range resources {
		reader := handlers[r.Type].(cloudformation.ResourceReader)
		if _, err = reader.Read(ctx, r); err != nil {
			t.Fatalf("recover %s: %v", r.Type, err)
		}
		if recoverer, ok := handlers[r.Type].(cloudformation.ResourceCreationRecoverer); ok {
			replay := r
			replay.PhysicalID = ""
			got, err := recoverer.RecoverCreation(ctx, replay)
			if err != nil || got.PhysicalID != r.PhysicalID {
				t.Fatalf("same-token recovery of reopened %s: %v, %v", r.Type, got, err)
			}
		}
		wrong := r
		wrong.Token = "foreign-incarnation"
		if err = handlers[r.Type].Delete(ctx, wrong); err == nil {
			t.Fatalf("foreign incarnation deleted persisted %s", r.Type)
		}
		if recoverer, ok := handlers[r.Type].(cloudformation.ResourceCreationRecoverer); ok {
			replay := wrong
			replay.PhysicalID = ""
			if got, err := recoverer.RecoverCreation(ctx, replay); err == nil || got.PhysicalID != "" {
				t.Fatalf("foreign incarnation recovered reopened %s: %v, %v", r.Type, got, err)
			}
		}
		direct := r
		direct.CloudControl = true
		direct.Properties = nil
		current, err := reader.Read(ctx, direct)
		if err != nil {
			t.Fatalf("direct authoritative read %s: %v", r.Type, err)
		}
		if r.Type == metadata.Type {
			for _, key := range []string{"SchemaVersionId", "Key", "Value"} {
				if current[key] != r.Properties[key] {
					t.Fatalf("reopened metadata %s = %#v; want %#v", key, current[key], r.Properties[key])
				}
			}
		}
	}
}
