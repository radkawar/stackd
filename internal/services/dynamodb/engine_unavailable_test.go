package dynamodb

import (
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

func retainedTable(scope Scope, name string, ttl api.TimeToLiveDescription) TableRecord {
	key := TableKey{Scope: scope, Name: name}
	return TableRecord{Key: key, DatabaseID: "database", PhysicalName: "table_" + name, TTL: ttl, Data: api.TableDescription{
		TableName: new(api.TableName(name)), TableArn: new(api.String(key.ARN())), TableStatus: new(api.TableStatusACTIVE),
		KeySchema:            api.KeySchema{{AttributeName: new(api.KeySchemaAttributeName("pk")), KeyType: new(api.KeyTypeHASH)}},
		AttributeDefinitions: api.AttributeDefinitions{{AttributeName: new(api.KeySchemaAttributeName("pk")), AttributeType: new(api.ScalarAttributeTypeS)}},
		BillingModeSummary:   &api.BillingModeSummary{BillingMode: new(api.BillingModePAY_PER_REQUEST)},
	}}
}

// A table retained from a run with DynamoDB Local must not accept lifecycle
// intents that only the absent engine can complete; it remains ACTIVE rather
// than reporting UPDATING, DELETING or an enabled feature that never runs.
func TestRetainedTableRejectsEngineEffectsWithoutRuntime(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	scope := Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	retained := retainedTable(scope, "retained", api.TimeToLiveDescription{TimeToLiveStatus: new(api.TimeToLiveStatusDISABLED)})
	expiring := retainedTable(scope, "expiring", api.TimeToLiveDescription{TimeToLiveStatus: new(api.TimeToLiveStatusENABLED), AttributeName: new(api.TimeToLiveAttributeName("ttl"))})
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutTable(retained); err != nil {
			return err
		}
		return tx.PutTable(expiring)
	}); err != nil {
		t.Fatal(err)
	}
	model, _ := awscatalog.LookupService("dynamodb")
	call := func(operation string, input any) string {
		op, ok := model.Operation(operation)
		if !ok {
			t.Fatalf("missing operation %s", operation)
		}
		if _, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}); rejected != nil {
			return rejected.Code
		}
		return ""
	}
	name := new(api.TableArn("retained"))
	for operation, input := range map[string]any{
		"UpdateTable":                       &api.UpdateTableInput{TableName: name, DeletionProtectionEnabled: new(api.DeletionProtectionEnabled(true))},
		"DeleteTable":                       &api.DeleteTableInput{TableName: name},
		"UpdateTimeToLive":                  &api.UpdateTimeToLiveInput{TableName: name, TimeToLiveSpecification: &api.TimeToLiveSpecification{Enabled: new(api.TimeToLiveEnabled(true)), AttributeName: new(api.TimeToLiveAttributeName("ttl"))}},
		"EnableKinesisStreamingDestination": &api.EnableKinesisStreamingDestinationInput{TableName: name, StreamArn: new(api.StreamArn("arn:aws:kinesis:us-east-1:123456789012:stream/destination"))},
	} {
		if code := call(operation, input); code != "ServiceUnavailable" {
			t.Errorf("%s admitted without an engine: %q", operation, code)
		}
	}
	// Disabling TTL has no native effect to perform and remains available.
	if code := call("UpdateTimeToLive", &api.UpdateTimeToLiveInput{TableName: new(api.TableArn("expiring")), TimeToLiveSpecification: &api.TimeToLiveSpecification{Enabled: new(api.TimeToLiveEnabled(false)), AttributeName: new(api.TimeToLiveAttributeName("ttl"))}}); code != "" {
		t.Fatalf("TTL disable rejected: %s", code)
	}
	if err := repository.View(ctx, func(r Reader) error {
		table, err := r.Table(retained.Key)
		if err != nil {
			return err
		}
		protected := table.Data.DeletionProtectionEnabled != nil && bool(*table.Data.DeletionProtectionEnabled)
		if value(table.Data.TableStatus) != "ACTIVE" || table.PendingUpdate != nil || value(table.TTL.TimeToLiveStatus) != "DISABLED" || protected {
			t.Fatalf("rejected intent changed the retained table: %+v", table)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
