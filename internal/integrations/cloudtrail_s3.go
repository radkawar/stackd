package integrations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/kms"
)

// S3LogCommands is the actual bucket/permission/object boundary used by trails.
type S3LogCommands interface {
	GetBucketACL(context.Context, *api.GetBucketAclInput) (*api.GetBucketAclOutput, *awswire.Error)
	PutObject(context.Context, *api.PutObjectInput) (*api.PutObjectOutput, *awswire.Error)
}

type CloudTrailS3 struct{ S3 S3LogCommands }

func trailContext(ctx context.Context, trail cloudtrail.TrailKey, parent string) context.Context {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: trail.Partition, AccountID: trail.AccountID, Region: trail.Region, RequestID: strings.ReplaceAll(uuid.NewString(), "-", ""), ParentEventID: parent})
	return awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "cloudtrail.amazonaws.com", SourceARN: trail.ARN(), Type: "AssumedRole"})
}
func (a CloudTrailS3) Validate(ctx context.Context, trail cloudtrail.TrailRecord, parent string) (string, *awswire.Error) {
	ctx = trailContext(ctx, trail.Key, parent)
	_, aclError := a.S3.GetBucketACL(ctx, &api.GetBucketAclInput{Bucket: new(api.BucketName(trail.Bucket))})
	prefix := trail.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	prefix += "AWSLogs/"
	if trail.OrganizationID != "" {
		prefix += trail.OrganizationID + "/"
	}
	keyID := trailKeyReference(trail.Key, trail.KMSKeyID)
	// Native admission writes an encrypted zero-byte marker. Its S3 command
	// owns key resolution, KMS authority and the actual object policy gate.
	out, putError := a.put(ctx, trail.Key, trail.Bucket, prefix+trail.Key.AccountID+"/CloudTrail/", keyID, nil, parent, "")
	var digestError *awswire.Error
	if trail.LogFileValidation {
		_, digestError = a.put(ctx, trail.Key, trail.Bucket, prefix+trail.Key.AccountID+"/CloudTrail-Digest/", keyID, nil, parent, "")
	}
	// AWS attempts the marker even when the ACL gate fails; that successful
	// S3 write remains after CreateTrail rejects the destination.
	if aclError != nil {
		return "", trailBucketError(aclError, trail.Bucket, keyID)
	}
	if putError != nil {
		return "", trailBucketError(putError, trail.Bucket, keyID)
	}
	if digestError != nil {
		return "", trailBucketError(digestError, trail.Bucket, keyID)
	}
	if out.SSEKMSKeyId != nil {
		return string(*out.SSEKMSKeyId), nil
	}
	return "", nil
}
func trailBucketError(wire *awswire.Error, bucket, keyID string) *awswire.Error {
	if wire.Code == "NoSuchBucket" {
		return &awswire.Error{Code: "S3BucketDoesNotExistException", Message: "The specified S3 bucket does not exist.", StatusCode: 400}
	}
	if wire.StatusCode >= 500 {
		return wire
	}
	if keyID != "" {
		if errors.Is(wire, kms.ErrInvalidKeyReference) {
			return &awswire.Error{Code: "KmsKeyNotFoundException", Message: fmt.Sprintf("KMS key ID %s does not exist, or S3 bucket %s and key are not in the same Region.", keyID, bucket), StatusCode: 400}
		}
		if strings.HasPrefix(wire.Code, "KMS.") && wire.Code != "KMS.NotFoundException" {
			return &awswire.Error{Code: "KmsException", Message: fmt.Sprintf("The trail cannot use KMS key %s. KMS Error Code: %s. KMS Error Message: %s", keyID, wire.Code, wire.Message), StatusCode: 400}
		}
		return &awswire.Error{Code: "InsufficientEncryptionPolicyException", Message: fmt.Sprintf("Insufficient permissions to access S3 bucket %s or KMS key %s.", bucket, keyID), StatusCode: 400}
	}
	return &awswire.Error{Code: "InsufficientS3BucketPolicyException", Message: "The S3 bucket policy does not permit CloudTrail log delivery.", StatusCode: 400}
}
func (a CloudTrailS3) Write(ctx context.Context, delivery cloudtrail.DeliveryRecord, keyID string, body []byte, parent string) *awswire.Error {
	_, wire := a.put(ctx, delivery.Trail, delivery.Bucket, delivery.ObjectKey, keyID, body, parent, delivery.DigestSignature)
	return wire
}
func (a CloudTrailS3) put(ctx context.Context, trail cloudtrail.TrailKey, bucket, key, keyID string, body []byte, parent, signature string) (*api.PutObjectOutput, *awswire.Error) {
	ctx = trailContext(ctx, trail, parent)
	in := &api.PutObjectInput{Bucket: new(api.BucketName(bucket)), Key: new(api.ObjectKey(key)), Body: body, ACL: new(api.ObjectCannedACL("bucket-owner-full-control")), ContentType: new(api.ContentType("application/json")), ContentEncoding: new(api.ContentEncoding("gzip")), ServerSideEncryption: new(api.ServerSideEncryption("AES256"))}
	if signature != "" {
		in.Metadata = api.Metadata{"signature": api.MetadataValue(signature), "signature-algorithm": api.MetadataValue("SHA256withRSA")}
	}
	if keyID != "" {
		encoded, _ := json.Marshal(struct {
			TrailARN string `json:"aws:cloudtrail:arn"`
		}{trail.ARN()})
		in.ServerSideEncryption = new(api.ServerSideEncryption("aws:kms"))
		in.SSEKMSKeyId = new(api.SSEKMSKeyId(keyID))
		in.SSEKMSEncryptionContext = new(api.SSEKMSEncryptionContext(base64.StdEncoding.EncodeToString(encoded)))
	}
	return a.S3.PutObject(ctx, in)
}

// Unqualified references belong to the trail's home Region, even when its
// destination bucket is elsewhere. S3 resolves aliases in the resulting ARN.
func trailKeyReference(trail cloudtrail.TrailKey, id string) string {
	if id == "" || strings.HasPrefix(id, "arn:") {
		return id
	}
	if !strings.HasPrefix(id, "alias/") {
		id = "key/" + id
	}
	return "arn:" + trail.Partition + ":kms:" + trail.Region + ":" + trail.AccountID + ":" + id
}
