package appsync

import (
	"stackd/clock"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/awsctx"
	"testing"
	"time"
)

func TestCloudFormationKeyRecoveryAndRecreationFence(t *testing.T) {
	timer := clock.NewManual(time.Date(2031, 2, 3, 4, 0, 0, 0, time.UTC))
	repository := NewMemoryRepository(nil)
	service := NewWithConfig(Config{Repository: repository, Clock: timer})
	t.Cleanup(func() { _ = service.Close() })
	k := Key{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", ID: "owned-api"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutAPI(APIRecord{Key: k}) }); err != nil {
		t.Fatal(err)
	}
	claim := "stack/logical/first"
	owned := WithCloudFormationOwnership(ctx, "ApiKey", claim, "", false, nil)
	input := &api.CreateApiKeyRequest{ApiId: new(api.String(k.ID)), Description: new(api.String("first"))}
	first, rejected := controlCall(service, owned, "CreateApiKey", input)
	if rejected != nil {
		t.Fatal(rejected)
	}
	key := first.(*api.CreateApiKeyResponse).ApiKey
	second, rejected := controlCall(service, owned, "CreateApiKey", input)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if value(second.(*api.CreateApiKeyResponse).ApiKey.Id) != value(key.Id) {
		t.Fatal("recovery created a second credential")
	}
	// Ordinary owner updates preserve the claim without exposing it in API DTOs.
	if _, rejected = controlCall(service, ctx, "UpdateApiKey", &api.UpdateApiKeyRequest{ApiId: input.ApiId, Id: key.Id, Description: new(api.String("changed"))}); rejected != nil {
		t.Fatal(rejected)
	}
	if err := repository.View(ctx, func(tx Reader) error {
		rows, err := tx.APIKeys(k)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Ownership != claim {
			t.Fatalf("ordinary mutation lost ownership: %#v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// An out-of-band reincarnation at the same public identifier is not ours.
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.DeleteAPIKey(k, value(key.Id)); err != nil {
			return err
		}
		return tx.PutAPIKey(APIKeyRecord{API: k, Key: *key})
	}); err != nil {
		t.Fatal(err)
	}
	deletion := WithCloudFormationOwnership(ctx, "ApiKey", claim, k.ID+"/"+value(key.Id), true, nil)
	if _, rejected = controlCall(service, deletion, "DeleteApiKey", &api.DeleteApiKeyRequest{ApiId: input.ApiId, Id: key.Id}); rejected == nil || rejected.Code != "ConflictException" {
		t.Fatalf("stale deletion was admitted: %v", rejected)
	}
	if err := repository.View(ctx, func(tx Reader) error {
		rows, err := tx.APIKeys(k)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			t.Fatal("stale delete removed recreated key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCloudFormationSchemaDeletionClearsExecutableOwnerAndIsRecoverable(t *testing.T) {
	repository := NewMemoryRepository(nil)
	service := NewWithConfig(Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	k := Key{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", ID: "schema-api"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutAPI(APIRecord{Key: k}) }); err != nil {
		t.Fatal(err)
	}
	owned := WithCloudFormationOwnership(ctx, "GraphQLSchema", "stack/schema/first", k.ID, false, nil)
	if _, rejected := controlCall(service, owned, "StartSchemaCreation", &api.StartSchemaCreationRequest{ApiId: new(api.String(k.ID)), Definition: api.Blob("type Query { value: String }")}); rejected != nil {
		t.Fatal(rejected)
	}
	if err := repository.View(ctx, func(tx Reader) error {
		record, err := tx.API(k)
		if err != nil {
			return err
		}
		if _, err = service.compiled(record); err != nil {
			t.Fatal(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deletion := WithCloudFormationSchemaDeletion(WithCloudFormationOwnership(ctx, "GraphQLSchema", "stack/schema/first", k.ID, true, nil))
	for range 2 {
		if _, rejected := controlCall(service, deletion, "StartSchemaCreation", &api.StartSchemaCreationRequest{ApiId: new(api.String(k.ID)), Definition: api.Blob{}}); rejected != nil {
			t.Fatal(rejected)
		}
	}
	if err := repository.View(ctx, func(tx Reader) error {
		record, err := tx.API(k)
		if err != nil {
			return err
		}
		if record.Schema != "" || record.SchemaOwnership != "" || record.SchemaStatus != "NOT_APPLICABLE" {
			t.Fatalf("schema deletion retained live owner: %#v", record)
		}
		if _, err = service.compiled(record); err == nil {
			t.Fatal("deleted schema remained executable through compiler cache")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
