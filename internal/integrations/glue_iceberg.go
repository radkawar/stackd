package integrations

import (
	"context"
	"net/url"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/glue"
	"stackd/internal/services/s3"
)

// GlueIcebergS3Commands is the existing caller-authorized object owner.
type GlueIcebergS3Commands interface {
	PutObject(context.Context, *api.PutObjectInput) (*api.PutObjectOutput, *awswire.Error)
	GetObject(context.Context, *api.GetObjectInput) (*s3.ObjectResponse[api.GetObjectOutput], *awswire.Error)
}

// GlueIcebergObjects uses the existing S3/KMS owner under the current caller's
// authority. Metadata bytes are external effects, never a second catalog store.
type GlueIcebergObjects struct{ S3 GlueIcebergS3Commands }

var _ glue.IcebergObjects = GlueIcebergObjects{}

func icebergObjectLocation(location string) (string, string, error) {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "s3" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimPrefix(u.Path, "/") == "" {
		return "", "", &awswire.Error{Code: "InvalidInputException", Message: "Iceberg metadata requires an S3 object location.", StatusCode: 400}
	}
	return u.Host, strings.TrimPrefix(u.Path, "/"), nil
}

func (a GlueIcebergObjects) Read(ctx context.Context, location string) ([]byte, error) {
	bucket, key, err := icebergObjectLocation(location)
	if err != nil {
		return nil, err
	}
	out, rejected := a.S3.GetObject(awsctx.WithViaService(ctx, "glue.amazonaws.com"), &api.GetObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key))})
	if rejected != nil {
		return nil, rejected
	}
	return out.Output.Body, nil
}

func (a GlueIcebergObjects) Write(ctx context.Context, location string, data []byte) error {
	bucket, key, err := icebergObjectLocation(location)
	if err != nil {
		return err
	}
	_, rejected := a.S3.PutObject(awsctx.WithViaService(ctx, "glue.amazonaws.com"), &api.PutObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key)), Body: data, ContentType: new(api.ContentType("application/json")), IfNoneMatch: new(api.IfNoneMatch("*"))})
	if rejected != nil {
		return rejected
	}
	return nil
}
