package integrations

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/kms"
)

// KMSDataKeys is the encryption boundary consumed by service data-key adapters.
type KMSDataKeys interface {
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Encrypt(context.Context, string, []byte, map[string]string) ([]byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
	IsAWSManagedKey(context.Context, string) (bool, error)
}

// IAMActivity records use of an authenticated IAM credential.
type IAMActivity interface {
	RecordActivity(context.Context, string, string) error
}

// ServiceDataKeys preserves the command's principal when its service calls KMS.
type ServiceDataKeys struct {
	KMS      KMSDataKeys
	Activity IAMActivity
	Service  string
}

func (k ServiceDataKeys) GenerateDataKey(ctx context.Context, id string, ec map[string]string) ([]byte, []byte, string, *awswire.Error) {
	if err := recordKMSActivity(ctx, k.Activity, "GenerateDataKey"); err != nil {
		return nil, nil, "", err
	}
	return k.KMS.GenerateDataKey(kms.WithViaService(ctx, k.Service), id, ec)
}

func (k ServiceDataKeys) Encrypt(ctx context.Context, id string, plain []byte, ec map[string]string) ([]byte, string, *awswire.Error) {
	if err := recordKMSActivity(ctx, k.Activity, "Encrypt"); err != nil {
		return nil, "", err
	}
	return k.KMS.Encrypt(kms.WithViaService(ctx, k.Service), id, plain, ec)
}

func (k ServiceDataKeys) Decrypt(ctx context.Context, cipher []byte, ec map[string]string) ([]byte, string, *awswire.Error) {
	if err := recordKMSActivity(ctx, k.Activity, "Decrypt"); err != nil {
		return nil, "", err
	}
	return k.KMS.Decrypt(kms.WithViaService(ctx, k.Service), cipher, ec)
}

func (k ServiceDataKeys) EnsureServiceKey(ctx context.Context, service string) (string, *awswire.Error) {
	return k.KMS.EnsureServiceKey(kms.WithViaService(ctx, k.Service), service)
}

// IsAWSManagedKey reads the immutable owner metadata, without introducing a
// DescribeKey permission or audit event into resource sharing.
func (k ServiceDataKeys) IsAWSManagedKey(ctx context.Context, arn string) (bool, error) {
	prefix, rest, ok := strings.Cut(arn, ":")
	if !ok || prefix != "arn" {
		return false, errors.New("key ownership requires a canonical KMS key ARN")
	}
	partition, rest, _ := strings.Cut(rest, ":")
	service, rest, _ := strings.Cut(rest, ":")
	region, rest, _ := strings.Cut(rest, ":")
	account, resource, _ := strings.Cut(rest, ":")
	if service != "kms" || partition == "" || region == "" || account == "" || !strings.HasPrefix(resource, "key/") {
		return false, errors.New("key ownership requires a canonical KMS key ARN")
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.Region, metadata.AccountID = partition, region, account
	return k.KMS.IsAWSManagedKey(awsctx.WithMetadata(ctx, metadata), arn)
}

func recordKMSActivity(ctx context.Context, activity IAMActivity, operation string) *awswire.Error {
	// A trusted service principal has no IAM credential to record. KMS still
	// evaluates its key policy and source context on the actual operation.
	if awsctx.FromContext(ctx).ServicePrincipal.Name != "" {
		return nil
	}
	if err := activity.RecordActivity(ctx, "kms", operation); err != nil {
		return &awswire.Error{Code: "ServiceFailure", Message: "Unable to record authenticated activity.", StatusCode: 500}
	}
	return nil
}
