package s3

import (
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func TestTypedOwnershipControls(t *testing.T) {
	service := New(Config{})
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
	model, _ := awscatalog.LookupService("s3")
	call := func(name string, input any) (any, *awswire.Error) {
		operation, _ := model.Operation(name)
		return service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
	}
	bucket := new(api.BucketName("typed-ownership"))
	if _, wire := call("CreateBucket", &api.CreateBucketInput{Bucket: bucket}); wire != nil {
		t.Fatal(wire)
	}
	if _, wire := call("PutBucketOwnershipControls", &api.PutBucketOwnershipControlsInput{Bucket: bucket, OwnershipControls: &api.OwnershipControls{Rules: api.OwnershipControlsRules{{ObjectOwnership: new(api.ObjectOwnership("ObjectWriter"))}}}}); wire != nil {
		t.Fatal(wire)
	}
	if _, wire := call("PutBucketOwnershipControls", &api.PutBucketOwnershipControlsInput{Bucket: bucket}); wire == nil || wire.Code != "MissingRequestBodyError" {
		t.Fatalf("missing control input = %v", wire)
	}
	output, wire := call("GetBucketOwnershipControls", &api.GetBucketOwnershipControlsInput{Bucket: bucket})
	if wire != nil {
		t.Fatal(wire)
	}
	controls := output.(*api.GetBucketOwnershipControlsOutput).OwnershipControls
	if controls == nil || len(controls.Rules) != 1 || controls.Rules[0].ObjectOwnership == nil || *controls.Rules[0].ObjectOwnership != "ObjectWriter" {
		t.Fatalf("ownership mode after typed update and rejected empty input = %#v", controls)
	}
}
