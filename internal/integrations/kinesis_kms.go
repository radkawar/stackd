package integrations

import (
	"context"
	"strings"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/kinesis"
	"stackd/internal/services/kms"
)

// KinesisKMSOperations is implemented by kms.Service, including its key policy,
// grant, key state and transactional audit checks.
type KinesisKMSOperations interface {
	DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
}

// KinesisKeys forwards the authenticated producer/consumer, never substitutes a
// service principal for customer-key authorization.
type KinesisKeys struct {
	KMS      KinesisKMSOperations
	Activity IAMActivity
}

var _ kinesis.EncryptionKeys = KinesisKeys{}

func kinesisKMSContext(ctx context.Context, stream kinesis.StreamKey) context.Context {
	m := awsctx.FromContext(ctx)
	// Routing may change, but the caller account and all credential/session
	// attributes must survive cross-account stream access.
	m.Region, m.Partition = stream.Region, stream.Partition
	return kms.WithViaService(awsctx.WithMetadata(ctx, m), "kinesis")
}

func kinesisKeyError(err *awswire.Error) *awswire.Error {
	if err == nil {
		return nil
	}
	code := "InternalFailureException"
	switch err.Code {
	case "AccessDeniedException":
		code = "KMSAccessDeniedException"
	case "DisabledException":
		code = "KMSDisabledException"
	case "KMSInvalidStateException", "InvalidKeyUsageException", "IncorrectKeyException", "InvalidCiphertextException":
		code = "KMSInvalidStateException"
	case "NotFoundException":
		code = "KMSNotFoundException"
	case "OptInRequired", "KMSOptInRequired":
		code = "KMSOptInRequired"
	case "ThrottlingException", "LimitExceededException":
		code = "KMSThrottlingException"
	case "ValidationException":
		code = "InvalidArgumentException"
	}
	status := 400
	if code == "InternalFailureException" {
		status = 500
	}
	return &awswire.Error{Code: code, Message: err.Message, StatusCode: status}
}

func kinesisKeyScope(stream kinesis.StreamKey, arn string) *awswire.Error {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != stream.Partition || parts[2] != "kms" || parts[3] != stream.Region || parts[4] == "" || !strings.HasPrefix(parts[5], "key/") {
		return &awswire.Error{Code: "KMSInvalidStateException", Message: "The KMS key must be a key in the stream's Region and partition.", StatusCode: 400}
	}
	return nil
}

func (k KinesisKeys) keyIdentifier(ctx context.Context, stream kinesis.StreamKey, identifier string) (string, *awswire.Error) {
	defaultARN := "arn:" + stream.Partition + ":kms:" + stream.Region + ":" + stream.AccountID + ":alias/aws/kinesis"
	if identifier != "alias/aws/kinesis" && identifier != defaultARN {
		return identifier, nil
	}
	// EnsureServiceKey creates an actual regional managed key with a ViaService
	// policy. Foreign readers/producers resolve the owner's alias, not their own.
	if awsctx.FromContext(ctx).AccountID != stream.AccountID {
		return defaultARN, nil
	}
	arn, err := k.KMS.EnsureServiceKey(ctx, "kinesis")
	return arn, kinesisKeyError(err)
}

func (k KinesisKeys) ResolveKey(ctx context.Context, stream kinesis.StreamKey, identifier string) (string, *awswire.Error) {
	ctx = kinesisKMSContext(ctx, stream)
	id, err := k.keyIdentifier(ctx, stream, identifier)
	if err != nil {
		return "", err
	}
	if err = recordKMSActivity(ctx, k.Activity, "DescribeKey"); err != nil {
		return "", kinesisKeyError(err)
	}
	metadata, err := k.KMS.DescribeKey(ctx, id)
	if err != nil {
		return "", kinesisKeyError(err)
	}
	if metadata == nil || metadata.Arn == nil || metadata.KeySpec == nil || string(*metadata.KeySpec) != "SYMMETRIC_DEFAULT" || metadata.KeyUsage == nil || string(*metadata.KeyUsage) != "ENCRYPT_DECRYPT" {
		return "", &awswire.Error{Code: "KMSInvalidStateException", Message: "Kinesis requires a symmetric encryption KMS key.", StatusCode: 400}
	}
	if metadata.KeyState != nil && string(*metadata.KeyState) == "Disabled" {
		return "", &awswire.Error{Code: "KMSDisabledException", Message: "The KMS key is disabled.", StatusCode: 400}
	}
	if metadata.KeyState == nil || string(*metadata.KeyState) != "Enabled" {
		return "", &awswire.Error{Code: "KMSInvalidStateException", Message: "The KMS key is not enabled for encryption.", StatusCode: 400}
	}
	arn := string(*metadata.Arn)
	return arn, kinesisKeyScope(stream, arn)
}

func (k KinesisKeys) GenerateDataKey(ctx context.Context, stream kinesis.StreamKey, identifier string) ([]byte, []byte, string, *awswire.Error) {
	ctx = kinesisKMSContext(ctx, stream)
	id, err := k.keyIdentifier(ctx, stream, identifier)
	if err != nil {
		return nil, nil, "", err
	}
	if err = recordKMSActivity(ctx, k.Activity, "GenerateDataKey"); err != nil {
		return nil, nil, "", kinesisKeyError(err)
	}
	plain, wrapped, arn, err := k.KMS.GenerateDataKey(ctx, id, map[string]string{"aws:kinesis:arn": stream.ARN()})
	if err != nil {
		clear(plain)
		return nil, nil, "", kinesisKeyError(err)
	}
	if err = kinesisKeyScope(stream, arn); err != nil {
		clear(plain)
		return nil, nil, "", err
	}
	return plain, wrapped, arn, nil
}

func (k KinesisKeys) Decrypt(ctx context.Context, stream kinesis.StreamKey, wrapped []byte) ([]byte, string, *awswire.Error) {
	ctx = kinesisKMSContext(ctx, stream)
	if err := recordKMSActivity(ctx, k.Activity, "Decrypt"); err != nil {
		return nil, "", kinesisKeyError(err)
	}
	plain, arn, err := k.KMS.Decrypt(ctx, wrapped, map[string]string{"aws:kinesis:arn": stream.ARN()})
	if err != nil {
		clear(plain)
		return nil, "", kinesisKeyError(err)
	}
	if err = kinesisKeyScope(stream, arn); err != nil {
		clear(plain)
		return nil, "", err
	}
	return plain, arn, nil
}
