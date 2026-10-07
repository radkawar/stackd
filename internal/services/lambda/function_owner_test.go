package lambda

import (
	"testing"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func TestFunctionOwnerCopiedTagsCannotClaimRecreatedName(t *testing.T) {
	key := FunctionKey{Scope: Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "recreated"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.Account, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: key.Account})
	service := New(Config{})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	owner := FunctionOwner{StackID: "stack-original", LogicalID: "Function", Token: "first-incarnation"}
	original := FunctionRecord{Key: key, Runtime: "python3.12", Handler: "index.handler", Revision: "original", DeploymentRevision: "original", State: "Active", Owner: owner, Tags: map[string]string{"stackd:cloudformation:owner": "copied-public-marker"}}
	if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutFunction(original) }); err != nil {
		t.Fatal(err)
	}
	owned := WithFunctionOwner(ctx, owner)
	if _, wire := service.getConfiguration(owned, &api.GetFunctionConfigurationInput{FunctionName: new(api.NamespacedFunctionName(key.Name))}); wire != nil {
		t.Fatal(wire)
	}
	// Native tagging never changes the private claim.
	if _, wire := service.tagResource(ctx, &api.TagResourceInput{Resource: new(api.TaggableResource(key.ARN())), Tags: api.Tags{"customer": "new-value"}}); wire != nil {
		t.Fatal(wire)
	}
	if _, wire := service.deleteFunction(ctx, &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name))}); wire != nil {
		t.Fatal(wire)
	}
	recreated := original
	recreated.Revision, recreated.DeploymentRevision, recreated.Owner = "recreated", "recreated", FunctionOwner{}
	if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutFunction(recreated) }); err != nil {
		t.Fatal(err)
	}
	for action, call := range map[string]func() *awswire.Error{
		"get": func() *awswire.Error {
			_, wire := service.getConfiguration(owned, &api.GetFunctionConfigurationInput{FunctionName: new(api.NamespacedFunctionName(key.Name))})
			return wire
		},
		"tag": func() *awswire.Error {
			_, wire := service.tagResource(owned, &api.TagResourceInput{Resource: new(api.TaggableResource(key.ARN())), Tags: api.Tags{"customer": "unwanted"}})
			return wire
		},
		"delete": func() *awswire.Error {
			_, wire := service.deleteFunction(owned, &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name))})
			return wire
		},
	} {
		if wire := call(); wire == nil || wire.Code != "AccessDeniedException" {
			t.Fatalf("%s accepted copied public tags: %v", action, wire)
		}
	}
	if err := service.repository.View(ctx, func(r Reader) error {
		record, err := r.Function(key)
		if err == nil && record.Revision != "recreated" {
			t.Fatalf("stale owner mutated replacement: %+v", record)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
