package identitystore_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/identitystore"
	"stackd/internal/awsctx"
	service "stackd/internal/services/identitystore"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/identitystore"
)

// This exercises real directory admission, recovery, mutation and deletion.
// A later group with the same display name must not be adopted by an old stack.
func TestCloudFormationGroupRecoveryAndIncarnationOwnership(t *testing.T) {
	scope := service.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
	path := filepath.Join(t.TempDir(), "directory.sqlite")
	db, e := sqlite.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := db.Close(); e != nil {
			t.Error(e)
		}
	})
	repo := backend.New(db)
	s := service.NewWithConfig(service.Config{Repository: repo})
	const store = "d-0123456789"
	if e := s.EnsureStore(ctx, scope, store); e != nil {
		t.Fatal(e)
	}
	invoke := func(ctx context.Context, op string, input map[string]any) (any, error) {
		raw, e := json.Marshal(input)
		if e != nil {
			return nil, e
		}
		req, e := api.DecodeRequest(op, awsapi.Request{JSON: raw})
		if e != nil {
			return nil, e
		}
		out, rejected := s.ExecuteCommand(ctx, req)
		if rejected != nil {
			return nil, rejected
		}
		return out, nil
	}
	owned := service.WithCloudFormationOwner(ctx, "stack/logical/incarnation-one")
	input := map[string]any{"IdentityStoreId": store, "DisplayName": "Operators"}
	first, e := invoke(owned, "CreateGroup", input)
	if e != nil {
		t.Fatal(e)
	}
	id := first.(*api.CreateGroupOutput).GroupId
	// Close/reopen storage as well as replacing the service process.
	if e := db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = sqlite.Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	repo = backend.New(db)
	s = service.NewWithConfig(service.Config{Repository: repo})
	second, e := invoke(owned, "CreateGroup", input)
	if e != nil {
		t.Fatal(e)
	}
	if *second.(*api.CreateGroupOutput).GroupId != *id {
		t.Fatal("recovery allocated another group")
	}
	other := service.WithCloudFormationOwner(ctx, "stack/logical/incarnation-two")
	if _, e := invoke(other, "CreateGroup", input); e == nil {
		t.Fatal("another incarnation adopted an existing group")
	}
	deletion := map[string]any{"IdentityStoreId": store, "GroupId": string(*id)}
	if _, e := invoke(other, "DeleteGroup", deletion); e == nil {
		t.Fatal("another incarnation deleted the owned group")
	}
	if _, e := invoke(owned, "UpdateGroup", map[string]any{"IdentityStoreId": store, "GroupId": string(*id), "Operations": []any{map[string]any{"AttributePath": "description", "AttributeValue": "on-call"}}}); e != nil {
		t.Fatal(e)
	}
	if _, e := invoke(owned, "DeleteGroup", deletion); e != nil {
		t.Fatal(e)
	}
	recreated, e := invoke(ctx, "CreateGroup", input)
	if e != nil {
		t.Fatal(e)
	}
	recreatedID := recreated.(*api.CreateGroupOutput).GroupId
	if *recreatedID == *id {
		t.Fatal("direct recreation reused a deleted group ID")
	}
	if _, e := invoke(owned, "CreateGroup", input); e == nil {
		t.Fatal("old incarnation adopted a direct recreation")
	}
	if _, e := invoke(owned, "DeleteGroup", map[string]any{"IdentityStoreId": store, "GroupId": string(*recreatedID)}); e == nil {
		t.Fatal("old incarnation deleted a direct recreation")
	}
}
