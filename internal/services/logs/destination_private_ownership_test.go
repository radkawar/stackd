package logs

import (
	"context"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Exercise the real native preflight and post-external-check admission steps.
// External delivery is deliberately outside both repository transactions;
// replacement between them must invalidate the private row authority.
func TestCloudFormationDestinationPrivateAdmissionRechecksActualRow(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	create := WithCloudFormationOwner(ctx, "private-incarnation", true)
	mutate := WithCloudFormationOwner(ctx, "private-incarnation", false)
	input := DestinationRecord{Key: DestinationKey{Scope: scopeFor(ctx), Name: "owned-destination"}, TargetARN: "arn:aws:kinesis:us-east-1:123456789012:stream/target", RoleARN: "arn:aws:iam::123456789012:role/logs"}
	admit := func(ctx context.Context, input DestinationRecord) (DestinationRecord, *awswire.Error) {
		t.Helper()
		var out DestinationRecord
		var wire *awswire.Error
		err := repository.Update(ctx, func(tx Transaction) error {
			out, wire = service.prepareDestination(tx, input, nil)
			if wire != nil {
				return wire
			}
			return tx.PutDestination(out)
		})
		if err != nil && wire == nil {
			t.Fatal(err)
		}
		return out, wire
	}
	first, wire := admit(create, input)
	if wire != nil || first.CFNOwner != "private-incarnation" {
		t.Fatalf("native row was not privately admitted: %+v %v", first, wire)
	}
	call := func(ctx context.Context, operation string, input any) (any, *awswire.Error) {
		model, _ := awscatalog.LookupService("logs")
		op, _ := model.Operation(operation)
		return service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	}
	forged := api.Tags{"stackd:cloudformation:owner": "counterfeit", "stackd:cloudformation:stack-id": "stack", "stackd:cloudformation:logical-id": "Destination", "stackd:cloudformation:incarnation": "counterfeit"}
	if _, wire := call(ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.AmazonResourceName(input.Key.ARN())), Tags: forged}); wire != nil {
		t.Fatal(wire)
	}
	var prepared DestinationRecord
	if err := repository.View(mutate, func(r Reader) error {
		var w *awswire.Error
		prepared, w = service.prepareDestination(r, input, nil)
		if w != nil {
			return w
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, wire := admit(WithCloudFormationOwner(ctx, "counterfeit", true), input); wire == nil {
		t.Fatal("public marker forged native admission")
	}
	// A direct native delete/recreate with copied public tags loses the old claim.
	if _, wire := call(ctx, "DeleteDestination", &api.DeleteDestinationRequest{DestinationName: new(api.DestinationName(input.Key.Name))}); wire != nil {
		t.Fatal(wire)
	}
	replacement, wire := admit(ctx, input)
	if wire != nil {
		t.Fatal(wire)
	}
	if replacement.CFNOwner != "" {
		t.Fatal("native replacement inherited a deleted claim")
	}
	if _, wire := call(ctx, "TagResource", &api.TagResourceRequest{ResourceArn: new(api.AmazonResourceName(input.Key.ARN())), Tags: forged}); wire != nil {
		t.Fatal(wire)
	}
	if _, wire := admit(mutate, prepared); wire == nil {
		t.Fatal("post-external-check transaction adopted foreign recreation")
	}
	if _, wire := call(mutate, "DeleteDestination", &api.DeleteDestinationRequest{DestinationName: new(api.DestinationName(input.Key.Name))}); wire == nil {
		t.Fatal("stale mutation deleted foreign recreation")
	}
	if _, wire := call(ctx, "ListTagsForResource", &api.ListTagsForResourceRequest{ResourceArn: new(api.AmazonResourceName(input.Key.ARN()))}); wire != nil {
		t.Fatalf("stale mutation damaged native destination: %v", wire)
	}
}
