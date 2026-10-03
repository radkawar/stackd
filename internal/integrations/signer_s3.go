package integrations

import (
	"context"
	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/s3"
)

type SignerS3Commands interface {
	GetObject(context.Context, *api.GetObjectInput) (*s3.ObjectResponse[api.GetObjectOutput], *awswire.Error)
	PutObject(context.Context, *api.PutObjectInput) (*api.PutObjectOutput, *awswire.Error)
}
type SignerS3Objects struct{ S3 SignerS3Commands }

func signerObjectContext(ctx context.Context) context.Context {
	m := awsctx.FromContext(ctx)
	m.ParentEventID = apievents.EventID(ctx)
	m.RequestID = uuid.NewString()
	m.InvokedBy = "signer.amazonaws.com"
	m.SourceIP, m.UserAgent = "signer.amazonaws.com", "signer.amazonaws.com"
	m.TransportKnown, m.SecureTransport = true, true
	return awsctx.WithViaService(awsctx.WithMetadata(ctx, m), "signer.amazonaws.com")
}
func (a SignerS3Objects) Read(ctx context.Context, bucket, key, version string) ([]byte, error) {
	out, e := a.S3.GetObject(signerObjectContext(ctx), &api.GetObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key)), VersionId: new(api.ObjectVersionId(version))})
	if e != nil {
		return nil, e
	}
	if out.Region != awsctx.FromContext(ctx).Region {
		return nil, &awswire.Error{Code: "ValidationException", Message: "The signing source bucket must be in the signing job Region", StatusCode: 400}
	}
	return out.Output.Body, nil
}
func (a SignerS3Objects) Write(ctx context.Context, bucket, key string, body []byte) error {
	_, e := a.S3.PutObject(signerObjectContext(ctx), &api.PutObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key)), Body: body, ContentType: new(api.ContentType("application/zip"))})
	if e != nil {
		return e
	}
	return nil
}
