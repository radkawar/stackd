package integrations

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/kms"
)

// EventBusKMSOperations is the KMS command boundary used by event buses.
type EventBusKMSOperations interface {
	DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	GenerateDataKeyWithoutPlaintext(context.Context, string, map[string]string) ([]byte, string, *awswire.Error)
}

type EventBridgeBusKeys struct {
	KMS      EventBusKMSOperations
	Activity IAMActivity
}

func (k EventBridgeBusKeys) PrepareBusKey(ctx context.Context, source eventbridge.BusKey, identifier string, initialize bool) (string, *awswire.Error) {
	if err := recordKMSActivity(ctx, k.Activity, "DescribeKey"); err != nil {
		return "", busKeyFailure("DescribeKey", identifier, err)
	}
	metadata, rejected := k.KMS.DescribeKey(kms.WithViaService(ctx, "events"), identifier)
	if rejected != nil {
		return "", busKeyFailure("DescribeKey", identifier, rejected)
	}
	keyARN := string(*metadata.Arn)
	parsed, err := arn.Parse(keyARN)
	if err != nil || parsed.Partition != source.Partition || parsed.Region != source.Region {
		return "", &awswire.Error{Code: "ValidationException", Message: "The KMS key must be in the same Region as the event bus.", StatusCode: 400}
	}
	if metadata.KeySpec == nil || string(*metadata.KeySpec) != "SYMMETRIC_DEFAULT" || metadata.KeyUsage == nil || string(*metadata.KeyUsage) != "ENCRYPT_DECRYPT" {
		return "", &awswire.Error{Code: "ValidationException", Message: "The KMS key must be a symmetric encryption key.", StatusCode: 400}
	}
	if metadata.Enabled == nil || !bool(*metadata.Enabled) {
		return "", &awswire.Error{Code: "ValidationException", Message: "Parameter kmsKeyIdentifier is not valid. Reason: " + keyARN + " is disabled.", StatusCode: 400}
	}
	if initialize {
		if err := recordKMSActivity(ctx, k.Activity, "GenerateDataKeyWithoutPlaintext"); err != nil {
			return "", busKeyFailure("GenerateDataKeyWithoutPlaintext", keyARN, err)
		}
		_, _, rejected = k.KMS.GenerateDataKeyWithoutPlaintext(kms.WithViaService(ctx, "events"), keyARN, archiveEncryptionContext(source, ""))
		if rejected != nil {
			return "", busKeyFailure("GenerateDataKeyWithoutPlaintext", keyARN, rejected)
		}
	}
	plain, wrapped, _, rejected := k.GenerateBusDataKey(ctx, source, keyARN)
	clear(plain)
	if rejected != nil {
		return "", busKeyFailure("GenerateDataKey", keyARN, rejected)
	}
	plain, rejected = k.DecryptBusDataKey(ctx, source, wrapped)
	clear(plain)
	if rejected != nil {
		return "", busKeyFailure("Decrypt", keyARN, rejected)
	}
	if strings.HasPrefix(identifier, "alias/") {
		return fmt.Sprintf("arn:%s:kms:%s:%s:%s", source.Partition, source.Region, source.Account, identifier), nil
	}
	if strings.HasPrefix(identifier, "arn:") {
		return identifier, nil
	}
	return keyARN, nil
}

func (k EventBridgeBusKeys) GenerateBusDataKey(ctx context.Context, source eventbridge.BusKey, identifier string) ([]byte, []byte, string, *awswire.Error) {
	return k.KMS.GenerateDataKey(archiveKeyServiceContext(ctx, source), identifier, archiveEncryptionContext(source, ""))
}

func (k EventBridgeBusKeys) DecryptBusDataKey(ctx context.Context, source eventbridge.BusKey, wrapped []byte) ([]byte, *awswire.Error) {
	plain, _, rejected := k.KMS.Decrypt(archiveKeyServiceContext(ctx, source), wrapped, archiveEncryptionContext(source, ""))
	return plain, rejected
}

func (k EventBridgeBusKeys) DecryptBusConfiguration(ctx context.Context, source eventbridge.BusKey, wrapped []byte) ([]byte, *awswire.Error) {
	if rejected := recordKMSActivity(ctx, k.Activity, "Decrypt"); rejected != nil {
		return nil, busConfigurationFailure(rejected)
	}
	plain, _, rejected := k.KMS.Decrypt(kms.WithViaService(ctx, "events"), wrapped, archiveEncryptionContext(source, ""))
	if rejected != nil {
		return nil, busConfigurationFailure(rejected)
	}
	return plain, nil
}

func busConfigurationFailure(rejected *awswire.Error) *awswire.Error {
	if rejected.StatusCode >= 500 {
		return &awswire.Error{Code: "InternalException", Message: rejected.Message, StatusCode: 500}
	}
	return &awswire.Error{Code: "NotAuthorizedException", Message: "Cannot perform Kms:Decrypt on KMS key configured on event bus.", StatusCode: 400}
}

func busKeyFailure(action, identifier string, rejected *awswire.Error) *awswire.Error {
	if rejected == nil {
		return nil
	}
	if rejected.StatusCode >= 500 {
		return &awswire.Error{Code: "InternalException", Message: rejected.Message, StatusCode: 500}
	}
	code, message := "ValidationException", "Parameter "+identifier+" is not valid. Reason: "+rejected.Message
	if rejected.Code == "AccessDeniedException" && action != "GenerateDataKeyWithoutPlaintext" {
		code, message = "AccessDeniedException", "Access to call kms:"+action+" is denied. Reason: "+rejected.Message
	}
	return &awswire.Error{Code: code, Message: message, StatusCode: 400}
}
