package integrations

import (
	"context"

	"stackd/internal/awsapi"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/kms"
)

// EBSKMSOperations keeps snapshot encryption on the real KMS command boundary.
// Credential activity and API events retain the shared transaction context.
type EBSKMSOperations interface {
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	IsAWSManagedKey(context.Context, string) (bool, error)
}

// EBSSnapshotKeys forwards the snapshot caller, including its session policies.
// EBS owns the snapshot encryption contexts and maps the returned KMS errors.
type EBSSnapshotKeys struct {
	KMS      EBSKMSOperations
	Activity IAMActivity
}

func ebsKMSContext(ctx context.Context) context.Context {
	// Native EBS uses the EC2 KMS forwarding condition, but its audit origin is
	// EBS. Neither condition replaces the authenticated IAM/STS principal.
	ctx = kms.WithViaService(ctx, "ec2")
	metadata := awsctx.FromContext(ctx)
	metadata.InvokedBy = "ebs.amazonaws.com"
	if metadata.Partition == "aws-cn" {
		metadata.InvokedBy += ".cn"
	}
	metadata.SourceIP, metadata.UserAgent = metadata.InvokedBy, metadata.InvokedBy
	return awsctx.WithMetadata(ctx, metadata)
}

func ebsKMSEncryptionContext(encryption map[string]string) kmsapi.EncryptionContextType {
	if encryption == nil {
		return nil
	}
	result := make(kmsapi.EncryptionContextType, len(encryption))
	for key, value := range encryption {
		result[kmsapi.EncryptionContextKey(key)] = kmsapi.EncryptionContextValue(value)
	}
	return result
}

func (k EBSSnapshotKeys) command(ctx context.Context, name string, input any) (any, *awswire.Error) {
	ctx = ebsKMSContext(ctx)
	if rejected := recordKMSActivity(ctx, k.Activity, name); rejected != nil {
		return nil, rejected
	}
	model, _ := awscatalog.LookupService("kms")
	operation, _ := model.Operation(name)
	return k.KMS.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
}

func (k EBSSnapshotKeys) GenerateDataKey(ctx context.Context, keyID string, encryption map[string]string) ([]byte, []byte, string, *awswire.Error) {
	id, size := kmsapi.KeyIdType(keyID), kmsapi.NumberOfBytesType(64)
	output, rejected := k.command(ctx, "GenerateDataKey", &kmsapi.GenerateDataKeyInput{
		KeyId: &id, NumberOfBytes: &size, EncryptionContext: ebsKMSEncryptionContext(encryption),
	})
	if rejected != nil {
		return nil, nil, "", rejected
	}
	out := output.(*kmsapi.GenerateDataKeyOutput)
	return out.Plaintext, out.CiphertextBlob, string(*out.KeyId), nil
}

func (k EBSSnapshotKeys) Decrypt(ctx context.Context, wrapped []byte, encryption map[string]string) ([]byte, string, *awswire.Error) {
	ctx = ebsKMSContext(ctx)
	if rejected := recordKMSActivity(ctx, k.Activity, "Decrypt"); rejected != nil {
		return nil, "", rejected
	}
	return k.KMS.Decrypt(ctx, wrapped, encryption)
}

func (k EBSSnapshotKeys) ReEncrypt(ctx context.Context, wrapped []byte, keyID string, source, destination map[string]string) ([]byte, string, *awswire.Error) {
	id := kmsapi.KeyIdType(keyID)
	output, rejected := k.command(ctx, "ReEncrypt", &kmsapi.ReEncryptInput{
		CiphertextBlob: wrapped, DestinationKeyId: &id,
		SourceEncryptionContext: ebsKMSEncryptionContext(source), DestinationEncryptionContext: ebsKMSEncryptionContext(destination),
	})
	if rejected != nil {
		return nil, "", rejected
	}
	out := output.(*kmsapi.ReEncryptOutput)
	return out.CiphertextBlob, string(*out.KeyId), nil
}

func (k EBSSnapshotKeys) DescribeKey(ctx context.Context, keyID string) (string, *awswire.Error) {
	ctx = ebsKMSContext(ctx)
	if rejected := recordKMSActivity(ctx, k.Activity, "DescribeKey"); rejected != nil {
		return "", rejected
	}
	metadata, rejected := k.KMS.DescribeKey(ctx, keyID)
	if rejected != nil {
		return "", rejected
	}
	return string(*metadata.Arn), nil
}

func (k EBSSnapshotKeys) EnsureServiceKey(ctx context.Context, service string) (string, *awswire.Error) {
	return k.KMS.EnsureServiceKey(ebsKMSContext(ctx), service)
}

func (k EBSSnapshotKeys) IsAWSManagedKey(ctx context.Context, arn string) (bool, error) {
	return k.KMS.IsAWSManagedKey(ctx, arn)
}
