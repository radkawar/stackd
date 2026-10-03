package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

// ResourceTaggingReportS3 keeps all bucket, object, ACL and KMS authorization in
// S3. In particular, reporting must not overwrite the bucket's default encryption.
type ResourceTaggingReportS3 interface {
	GetBucketACL(context.Context, *api.GetBucketAclInput) (*api.GetBucketAclOutput, *awswire.Error)
	GetBucketLocation(context.Context, *api.GetBucketLocationInput) (*api.GetBucketLocationOutput, *awswire.Error)
	PutObject(context.Context, *api.PutObjectInput) (*api.PutObjectOutput, *awswire.Error)
}

type ResourceTaggingReports struct{ S3 ResourceTaggingReportS3 }

// Reports are a forward-access-session operation, not a service-principal grant:
// https://docs.aws.amazon.com/tag-editor/latest/userguide/tag-policies-orgs.html#bucket-policy
// Same-account identity permissions suffice; cross-account bucket permissions,
// session restrictions and explicit denies remain native S3 decisions. There is
// no report source ARN, so this adapter does not invent aws:SourceArn conditions.
func resourceTaggingReportContext(ctx context.Context) context.Context {
	m := awsctx.FromContext(ctx)
	m.InvokedBy = "tagpolicies.tag.amazonaws.com"
	return awsctx.WithViaService(awsctx.WithMetadata(ctx, m), "tagpolicies.tag.amazonaws.com")
}

func (r ResourceTaggingReports) ValidateDestination(ctx context.Context, bucket, _ string) error {
	if r.S3 == nil {
		return fmt.Errorf("resource tagging requires native S3 report delivery")
	}
	ctx = resourceTaggingReportContext(ctx)
	if _, rejected := r.S3.GetBucketACL(ctx, &api.GetBucketAclInput{Bucket: new(api.BucketName(bucket))}); rejected != nil {
		return resourceTaggingReportError(rejected)
	}
	location, rejected := r.S3.GetBucketLocation(ctx, &api.GetBucketLocationInput{Bucket: new(api.BucketName(bucket))})
	if rejected != nil {
		return resourceTaggingReportError(rejected)
	}
	// S3 represents us-east-1 with an absent LocationConstraint.
	if location.LocationConstraint != nil && *location.LocationConstraint != "" && *location.LocationConstraint != "us-east-1" {
		return &awswire.Error{Code: "InvalidParameterException", Message: "The report destination bucket must be in us-east-1.", StatusCode: 400}
	}
	return nil
}

// The report worker invokes this outside its transaction. A native object write
// survives a later report-status commit failure and remains recoverable under
// the worker's stable object key; no tag data is stored in this adapter.
func (r ResourceTaggingReports) Deliver(ctx context.Context, bucket, key, organizationID string, body []byte) error {
	if err := r.ValidateDestination(ctx, bucket, organizationID); err != nil {
		return err
	}
	_, rejected := r.S3.PutObject(resourceTaggingReportContext(ctx), &api.PutObjectInput{
		Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key)), Body: body,
		ACL: new(api.ObjectCannedACL("bucket-owner-full-control")), ContentType: new(api.ContentType("text/csv")),
	})
	if rejected != nil {
		return rejected
	}
	return nil
}

func resourceTaggingReportError(rejected *awswire.Error) *awswire.Error {
	if rejected.StatusCode >= 500 {
		return &awswire.Error{Code: "InternalServiceException", Message: "Unable to access the report destination: " + rejected.Message, StatusCode: 500, Cause: rejected}
	}
	return &awswire.Error{Code: "InvalidParameterException", Message: "Unable to access the report destination: " + rejected.Message, StatusCode: 400, Cause: rejected}
}

var _ tagging.Reports = ResourceTaggingReports{}
