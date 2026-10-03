package integrations

import (
	"context"
	"net/url"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/athena"
	"stackd/internal/services/s3"
)

type AthenaS3Commands interface {
	PutObject(context.Context, *api.PutObjectInput) (*api.PutObjectOutput, *awswire.Error)
	GetObject(context.Context, *api.GetObjectInput) (*s3.ObjectResponse[api.GetObjectOutput], *awswire.Error)
}

// AthenaS3 writes and reads real result objects through current S3/KMS and
// bucket-policy authority. Reads retain the requesting caller, not the submitter.
type AthenaS3 struct{ S3 AthenaS3Commands }

var _ athena.Results = AthenaS3{}

func athenaResultLocation(query athena.QueryRecord) (string, string, *awswire.Error) {
	if query.Data.ResultConfiguration == nil || query.Data.ResultConfiguration.OutputLocation == nil {
		return "", "", athenaResultError("Result output location is missing")
	}
	location, err := url.Parse(string(*query.Data.ResultConfiguration.OutputLocation))
	if err != nil || location.Scheme != "s3" || location.Host == "" || location.User != nil || location.RawQuery != "" || location.Fragment != "" || strings.TrimPrefix(location.Path, "/") == "" {
		return "", "", athenaResultError("Invalid S3 result output location")
	}
	return location.Host, strings.TrimPrefix(location.Path, "/"), nil
}
func athenaResultError(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidRequestException", Message: message, StatusCode: 400}
}

func (a AthenaS3) Write(ctx context.Context, query athena.QueryRecord, body []byte) *awswire.Error {
	if a.S3 == nil {
		return &awswire.Error{Code: "InternalServerException", Message: "S3 results owner is unavailable", StatusCode: 500}
	}
	bucket, key, err := athenaResultLocation(query)
	if err != nil {
		return err
	}
	config := query.Data.ResultConfiguration
	in := &api.PutObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key)), Body: body, ContentType: new(api.ContentType("text/csv"))}
	if strings.HasSuffix(key, ".txt") {
		in.ContentType = new(api.ContentType("text/plain"))
	}
	if query.RequesterPays {
		in.RequestPayer = new(api.RequestPayer("requester"))
	}
	if config.ExpectedBucketOwner != nil {
		in.ExpectedBucketOwner = new(api.AccountId(*config.ExpectedBucketOwner))
	}
	if config.AclConfiguration != nil && config.AclConfiguration.S3AclOption != nil {
		in.ACL = new(api.ObjectCannedACL("bucket-owner-full-control"))
	}
	if encryption := config.EncryptionConfiguration; encryption != nil && encryption.EncryptionOption != nil {
		switch *encryption.EncryptionOption {
		case "SSE_S3":
			in.ServerSideEncryption = new(api.ServerSideEncryption("AES256"))
		case "SSE_KMS":
			in.ServerSideEncryption = new(api.ServerSideEncryption("aws:kms"))
			if encryption.KmsKey != nil {
				in.SSEKMSKeyId = new(api.SSEKMSKeyId(*encryption.KmsKey))
			}
		default:
			// TODO: Comeback implement the Athena/S3 client-side KMS envelope;
			// never misrepresent CSE_KMS as server-side encryption.
			return &awswire.Error{Code: "InvalidRequestException", Message: "Client-side result encryption is not supported", StatusCode: 400}
		}
	}
	_, rejected := a.S3.PutObject(awsctx.WithViaService(ctx, "athena.amazonaws.com"), in)
	return rejected
}

func (a AthenaS3) Read(ctx context.Context, query athena.QueryRecord) ([]byte, *awswire.Error) {
	if a.S3 == nil {
		return nil, &awswire.Error{Code: "InternalServerException", Message: "S3 results owner is unavailable", StatusCode: 500}
	}
	bucket, key, err := athenaResultLocation(query)
	if err != nil {
		return nil, err
	}
	in := &api.GetObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key))}
	if query.RequesterPays {
		in.RequestPayer = new(api.RequestPayer("requester"))
	}
	if owner := query.Data.ResultConfiguration.ExpectedBucketOwner; owner != nil {
		in.ExpectedBucketOwner = new(api.AccountId(*owner))
	}
	out, rejected := a.S3.GetObject(awsctx.WithViaService(ctx, "athena.amazonaws.com"), in)
	if rejected != nil {
		return nil, rejected
	}
	return out.Output.Body, nil
}
