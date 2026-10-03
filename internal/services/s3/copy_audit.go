package s3

import (
	"context"
	"net/url"
	"strings"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
)

func (s *Service) copyCall(ctx context.Context, in *api.CopyObjectInput) *apiCall {
	c := s.transferCall(ctx, "CopyObject", value(in.Bucket), value(in.Key))
	c.params["x-amz-copy-source"] = value(in.CopySource)
	for _, header := range []struct{ name, value string }{
		{"x-amz-acl", value(in.ACL)},
		{"x-amz-server-side-encryption", value(in.ServerSideEncryption)},
		{"x-amz-server-side-encryption-aws-kms-key-id", value(in.SSEKMSKeyId)},
		{"x-amz-server-side-encryption-customer-algorithm", value(in.SSECustomerAlgorithm)},
		{"x-amz-copy-source-server-side-encryption-customer-algorithm", value(in.CopySourceSSECustomerAlgorithm)},
		{"x-amz-copy-source-if-match", value(in.CopySourceIfMatch)},
		{"x-amz-copy-source-if-none-match", value(in.CopySourceIfNoneMatch)},
		{"If-Match", value(in.IfMatch)},
		{"If-None-Match", value(in.IfNoneMatch)},
	} {
		if header.value != "" {
			c.params[header.name] = header.value
		}
	}
	return c
}

// Copy operations own source-read admission and observed object size. Their
// internal GetObject shares the outer extended request ID, not its request ID.
// This identity is audit-only: IAM and KMS use the original caller's authority.
func (s *Service) recordCopySource(ctx context.Context, copy, source *apiCall, object *ObjectRecord, err error) error {
	m := awsctx.FromContext(ctx)
	source.accessLogOperation = "REST.COPY.OBJECT_GET"
	if copy.name == "UploadPartCopy" {
		source.accessLogOperation = "REST.COPY.PART_GET"
	}
	m.RequestID = uuid.NewString()
	m.InvokedBy, m.SourceIP, m.UserAgent = "AWS Internal", "AWS Internal", "AWS Internal"
	if err != nil {
		source.key = strings.ReplaceAll(url.QueryEscape(source.key), "%2F", "/")
	}
	source.params = map[string]any{"bucketName": source.bucket, "key": source.key}
	wire := wireError(err)
	var objectSize int64
	if wire == nil {
		objectSize = object.Size
	} else if copy.name == "UploadPartCopy" && wire.Code == "NoSuchUpload" {
		objectSize = object.Size
		source.statusOverride = 200
	}
	source.additional = map[string]any{
		"x-amz-id-2":         copy.additional["x-amz-id-2"],
		"bytesTransferredIn": 0, "bytesTransferredOut": 0,
		"objectSize": objectSize,
	}
	if wire != nil && wire.Code == "PreconditionFailed" {
		// The internal read's native audit status is 200 even though both
		// events carry PreconditionFailed and CopyObject returns HTTP 412.
		source.statusOverride = 200
	}
	return s.recordObjectRead(awsctx.WithMetadata(ctx, m), source, object, wire)
}
