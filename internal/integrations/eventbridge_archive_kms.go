package integrations

import (
	"context"
	"fmt"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/kms"
)

// ArchiveKMSOperations is the KMS boundary used by EventBridge archives.
type ArchiveKMSOperations interface {
	DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	DecryptWithKey(context.Context, []byte, string, map[string]string) ([]byte, string, *awswire.Error)
	ReEncrypt(context.Context, []byte, string, map[string]string, map[string]string) ([]byte, *awswire.Error)
	ReEncryptToService(context.Context, []byte, map[string]string) ([]byte, *awswire.Error)
}

// EventBridgeArchiveKeys keeps caller forward-access checks separate from the
// EventBridge service principal used for stored pattern and event encryption.
type EventBridgeArchiveKeys struct {
	KMS      ArchiveKMSOperations
	Activity IAMActivity
}

func (k EventBridgeArchiveKeys) ResolveKey(ctx context.Context, _ eventbridge.BusKey, identifier string) (string, *awswire.Error) {
	if err := recordKMSActivity(ctx, k.Activity, "DescribeKey"); err != nil {
		return "", archiveKeyFailure("DescribeKey", identifier, false, err)
	}
	metadata, err := k.KMS.DescribeKey(kms.WithViaService(ctx, "events"), identifier)
	if err != nil {
		return "", archiveKeyFailure("DescribeKey", identifier, false, err)
	}
	return string(*metadata.Arn), nil
}

func (k EventBridgeArchiveKeys) PrepareKey(ctx context.Context, source eventbridge.BusKey, arn string) ([]byte, []byte, *awswire.Error) {
	if err := recordKMSActivity(ctx, k.Activity, "GenerateDataKey"); err != nil {
		return nil, nil, archiveKeyFailure("GenerateDataKey", arn, false, err)
	}
	callerKey, _, _, err := k.KMS.GenerateDataKey(kms.WithViaService(ctx, "events"), arn, archiveEncryptionContext(source, ""))
	clear(callerKey)
	if err != nil {
		return nil, nil, archiveKeyFailure("GenerateDataKey", arn, false, err)
	}
	plaintext, wrapped, err := k.GenerateDataKey(ctx, source, arn, "")
	if err != nil {
		return nil, nil, archiveKeyFailure("GenerateDataKey", arn, true, err)
	}
	opened, err := k.DecryptDataKey(ctx, source, wrapped, "", arn)
	clear(opened)
	if err != nil {
		clear(plaintext)
		return nil, nil, archiveKeyFailure("Decrypt", arn, true, err)
	}
	return plaintext, wrapped, nil
}

func (k EventBridgeArchiveKeys) DescribeKey(ctx context.Context, source eventbridge.BusKey, arn string) *awswire.Error {
	_, err := k.KMS.DescribeKey(archiveKeyServiceContext(ctx, source), arn)
	return archiveKeyFailure("DescribeKey", arn, true, err)
}

func (k EventBridgeArchiveKeys) GenerateDataKey(ctx context.Context, source eventbridge.BusKey, arn, ruleARN string) ([]byte, []byte, *awswire.Error) {
	ctx = archiveKeyServiceContext(ctx, source)
	if ruleARN != "" {
		// Ingress uses the managed-rule context. Retained storage uses only
		// the bus context, as do native archive ReEncrypt operations.
		ingress, _, _, err := k.KMS.GenerateDataKey(ctx, arn, archiveEncryptionContext(source, ruleARN))
		clear(ingress)
		if err != nil {
			return nil, nil, err
		}
	}
	plaintext, wrapped, _, err := k.KMS.GenerateDataKey(ctx, arn, archiveEncryptionContext(source, ""))
	return plaintext, wrapped, err
}

func (k EventBridgeArchiveKeys) DecryptDataKey(ctx context.Context, source eventbridge.BusKey, wrapped []byte, ruleARN, keyARN string) ([]byte, *awswire.Error) {
	plaintext, _, err := k.KMS.DecryptWithKey(archiveKeyServiceContext(ctx, source), wrapped, keyARN, archiveEncryptionContext(source, ruleARN))
	if err != nil && err.Code == "IncorrectKeyException" {
		err = &awswire.Error{Code: err.Code, StatusCode: err.StatusCode, Message: "The key ID in the request does not identify a CMK that can perform this operation."}
	}
	return plaintext, err
}

func (k EventBridgeArchiveKeys) ReEncryptDataKey(ctx context.Context, source eventbridge.BusKey, wrapped []byte, destination, ruleARN string) ([]byte, *awswire.Error) {
	ctx = archiveKeyServiceContext(ctx, source)
	encryption := archiveEncryptionContext(source, ruleARN)
	if destination == "" {
		return k.KMS.ReEncryptToService(ctx, wrapped, encryption)
	}
	return k.KMS.ReEncrypt(ctx, wrapped, destination, encryption, archiveEncryptionContext(source, ""))
}

func archiveEncryptionContext(source eventbridge.BusKey, ruleARN string) map[string]string {
	// TODO: Comeback match additional native AWS Encryption SDK caller context and KMS cache behavior; local envelopes do not emulate that framing.
	context := map[string]string{"aws:events:event-bus:arn": source.ARN()}
	if ruleARN != "" {
		context["aws:events:rule:arn"] = ruleARN
	}
	return context
}

func archiveKeyServiceContext(ctx context.Context, source eventbridge.BusKey) context.Context {
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: source.Partition, AccountID: source.Account, Region: source.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "events.amazonaws.com", SourceARN: source.ARN(), Type: "AWSService"},
	})
	return kms.WithViaService(ctx, "events")
}

func archiveKeyFailure(action, arn string, service bool, err *awswire.Error) *awswire.Error {
	if err == nil {
		return nil
	}
	if err.StatusCode >= 500 {
		return &awswire.Error{Code: "InternalException", Message: err.Message, StatusCode: 500}
	}
	message := err.Message
	switch err.Code {
	case "NotFoundException":
		message = "The provided KMS key does not exist. Please ensure that the key identifier is correct and your key exists in the same region as the event source."
	case "DisabledException":
		message = "The provided KMS key is disabled. Please enable the key."
	case "AccessDeniedException":
		if service || action == "DescribeKey" {
			principal := "you have"
			if service {
				principal = "events.amazonaws.com has"
			}
			message = fmt.Sprintf("KMS returned an access denied exception when calling the %s API for the key with ARN %s. Please ensure that %s permissions to access %s.", action, arn, principal, action)
		}
	}
	return &awswire.Error{Code: "ValidationException", Message: message, StatusCode: 400}
}
