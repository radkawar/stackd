package integrations

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awsenvelope"
	"stackd/internal/awswire"
	"stackd/internal/services/kms"
	"stackd/internal/services/lambda"
)

type LambdaFilterKMSOperations interface {
	DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
}

// LambdaFilterEncryption forwards configuring/retrieving callers to KMS but uses
// the regional Lambda service principal (not the execution role) for polling.
type LambdaFilterEncryption struct {
	KMS      LambdaFilterKMSOperations
	Activity IAMActivity
}

var _ lambda.FilterEncryption = LambdaFilterEncryption{}

func (a LambdaFilterEncryption) Resolve(ctx context.Context, mapping lambda.EventSourceMappingKey, identifier string) (string, *awswire.Error) {
	parsed, err := arn.Parse(identifier)
	if err != nil || parsed.Service != "kms" || parsed.Region != mapping.Region || parsed.Partition != mapping.Partition {
		return "", &awswire.Error{Code: "InvalidParameterValueException", Message: "KMSKeyArn must identify a KMS key in the event source mapping region.", StatusCode: 400}
	}
	if wire := recordKMSActivity(ctx, a.Activity, "DescribeKey"); wire != nil {
		return "", wire
	}
	metadata, wire := a.KMS.DescribeKey(kms.WithViaService(ctx, "lambda"), identifier)
	if wire != nil {
		return "", wire
	}
	return string(*metadata.Arn), nil
}

func (a LambdaFilterEncryption) Protect(ctx context.Context, mapping lambda.EventSourceMappingRecord, keyARN string, plain []byte) (*lambda.EncryptedMappingFilters, *awswire.Error) {
	signer, err := awsenvelope.NewSigner()
	if err != nil {
		return nil, filterCipherError()
	}
	functionARN := mapping.Function.ARN()
	encryptionContext := lambdaFilterContext(functionARN, mapping.EventSourceARN)
	encryptionContext["aws-crypto-public-key"] = signer.PublicKey()
	if wire := recordKMSActivity(ctx, a.Activity, "GenerateDataKey"); wire != nil {
		return nil, wire
	}
	key, wrapped, actual, wire := a.KMS.GenerateDataKey(kms.WithViaService(ctx, "lambda"), keyARN, encryptionContext)
	if wire != nil {
		return nil, wire
	}
	defer clear(key)
	if actual != keyARN {
		return nil, filterCipherError()
	}
	// Preserve the old envelope's mapping-ARN binding inside the authenticated
	// private payload, without inventing an additional native KMS context field.
	mappingARN := mapping.Key.ARN()
	if len(mappingARN) > 1<<16-1 {
		return nil, filterCipherError()
	}
	bound := make([]byte, 0, 2+len(mappingARN)+len(plain))
	bound = binary.BigEndian.AppendUint16(bound, uint16(len(mappingARN)))
	bound = append(bound, mappingARN...)
	bound = append(bound, plain...)
	defer clear(bound)
	delete(encryptionContext, "aws-crypto-public-key")
	content, err := signer.Seal(key, wrapped, keyARN, encryptionContext, bound)
	if err != nil {
		return nil, filterCipherError()
	}
	return &lambda.EncryptedMappingFilters{Content: content, DataKey: wrapped, FunctionARN: functionARN, Format: lambda.FilterEnvelopeSDK}, nil
}

func (a LambdaFilterEncryption) Unprotect(ctx context.Context, mapping lambda.EventSourceMappingRecord, processing bool) ([]byte, *awswire.Error) {
	encrypted := mapping.Settings.EncryptedFilters
	if encrypted == nil {
		return nil, filterCipherError()
	}
	expected := lambdaFilterContext(encrypted.FunctionARN, mapping.EventSourceARN)
	encryptionContext := expected
	switch encrypted.Format {
	case "":
		// Legacy rows have no public-key context; do not guess their format from
		// random nonce bytes or rewrite them while servicing a read.
	case lambda.FilterEnvelopeSDK:
		var err error
		encryptionContext, err = awsenvelope.EncryptionContext(encrypted.Content, expected)
		if err != nil || encryptionContext["aws-crypto-public-key"] == "" {
			return nil, filterCipherError()
		}
	default:
		return nil, filterCipherError()
	}
	if processing {
		origin := awsctx.FromContext(ctx)
		ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
			Partition: mapping.Key.Partition, AccountID: mapping.Key.Account, Region: mapping.Key.Region,
			RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
			ServicePrincipal: awsctx.ServicePrincipal{Name: "lambda." + mapping.Key.Region + ".amazonaws.com", SourceARN: mapping.Key.ARN(), Type: "AWSService"},
		})
	} else if wire := recordKMSActivity(ctx, a.Activity, "Decrypt"); wire != nil {
		return nil, wire
	}
	key, actual, wire := a.KMS.Decrypt(kms.WithViaService(ctx, "lambda"), encrypted.DataKey, encryptionContext)
	if wire != nil {
		return nil, wire
	}
	defer clear(key)
	if actual != mapping.Settings.KMSKeyARN {
		return nil, filterCipherError()
	}
	if encrypted.Format == "" {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, filterCipherError()
		}
		aead, err := cipher.NewGCM(block)
		if err != nil || len(encrypted.Content) < aead.NonceSize() {
			return nil, filterCipherError()
		}
		n := aead.NonceSize()
		plain, err := aead.Open(nil, encrypted.Content[:n], encrypted.Content[n:], []byte(mapping.Key.ARN()))
		if err != nil {
			return nil, filterCipherError()
		}
		return plain, nil
	}
	bound, err := awsenvelope.Open(key, encrypted.DataKey, actual, expected, encrypted.Content)
	if err != nil {
		return nil, filterCipherError()
	}
	mappingARN := mapping.Key.ARN()
	if len(bound) < 2 || int(binary.BigEndian.Uint16(bound)) != len(mappingARN) || len(bound)-2 < len(mappingARN) || !bytes.Equal(bound[2:2+len(mappingARN)], []byte(mappingARN)) {
		clear(bound)
		return nil, filterCipherError()
	}
	return bound[2+len(mappingARN):], nil
}

func lambdaFilterContext(functionARN, sourceARN string) map[string]string {
	return map[string]string{"aws:lambda:FunctionArn": functionARN, "aws:lambda:EventSourceArn": sourceARN}
}

func filterCipherError() *awswire.Error {
	return &awswire.Error{Code: "ServiceException", Message: "Unable to authenticate encrypted filter criteria.", StatusCode: 500}
}
