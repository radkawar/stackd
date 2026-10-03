package lambda

import (
	"errors"
	"testing"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/journal"
	"stackd/storage/memory"
)

func TestLayerPermissionOwnerEventFailureRollsBackPolicyAndReceipt(t *testing.T) {
	domain := memory.NewDomain()
	repo, events := NewMemoryRepository(domain), journal.NewMemory(domain)
	key := LayerPermissionKey{LayerVersionKey: LayerVersionKey{LayerKey: LayerKey{Scope: Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "atomic-permission"}, Version: 1}, StatementID: "owned"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.Account, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: key.Account})
	owner := LayerPermissionOwner{StackID: "stack", LogicalID: "Permission", Token: "token"}
	owned := WithLayerPermissionOwner(ctx, owner)
	if err := repo.Update(ctx, func(tx Transaction) error { return tx.PutLayerVersion(LayerVersionRecord{Key: key.LayerVersionKey}) }); err != nil {
		t.Fatal(err)
	}
	in := &api.AddLayerVersionPermissionInput{LayerName: new(api.LayerName(key.Name)), VersionNumber: new(api.LayerVersionNumber(key.Version)), StatementId: new(api.StatementId(key.StatementID)), Action: new(api.LayerPermissionAllowedAction("lambda:GetLayerVersion")), Principal: new(api.LayerPermissionAllowedPrincipal("*"))}
	failed := aliasOwnerService(t, Config{Repository: repo, APIEvents: rejectedAliasEvents{apievents.New(events)}})
	_, wire := failed.addLayerVersionPermission(owned, in)
	requireAliasOwnerCode(t, wire, "ServiceException")
	if err := repo.View(ctx, func(r Reader) error {
		if _, err := r.LayerPolicy(key.LayerVersionKey); !errors.Is(err, ErrNotFound) {
			t.Fatalf("event failure retained policy: %v", err)
		}
		if _, err := r.LayerPermissionOwner(key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("event failure retained receipt: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rows, err := events.Read(ctx, 0, 10); err != nil || len(rows) != 0 {
		t.Fatalf("failed Add retained API event: %+v %v", rows, err)
	}
	good := aliasOwnerService(t, Config{Repository: repo, APIEvents: apievents.New(events)})
	first, wire := good.addLayerVersionPermission(owned, in)
	if wire != nil {
		t.Fatal(wire)
	}
	_, wire = failed.addLayerVersionPermission(owned, in)
	requireAliasOwnerCode(t, wire, "ServiceException")
	_, wire = failed.removeLayerVersionPermission(owned, &api.RemoveLayerVersionPermissionInput{LayerName: in.LayerName, VersionNumber: in.VersionNumber, StatementId: in.StatementId})
	requireAliasOwnerCode(t, wire, "ServiceException")
	if err := repo.View(ctx, func(r Reader) error {
		got, err := r.LayerPermissionOwner(key)
		if err != nil || got != owner {
			t.Fatalf("failed recovery/delete changed receipt: %+v %v", got, err)
		}
		policy, err := r.LayerPolicy(key.LayerVersionKey)
		if err != nil || policy.Revision != string(*first.RevisionId) {
			t.Fatalf("failed recovery/delete changed policy: %+v %v", policy, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rows, err := events.Read(ctx, 0, 10); err != nil || len(rows) != 1 || rows[0].APICallCompleted == nil || rows[0].APICallCompleted.EventName != "AddLayerVersionPermission20181031" {
		t.Fatalf("failed recovery/delete retained API event: %+v %v", rows, err)
	}
}
