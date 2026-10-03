package integrations

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awsapi"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/kms"
	"stackd/internal/services/lambda"
)

type LambdaDurableKMSOperations interface {
	LambdaFilterKMSOperations
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}

type LambdaDurableEncryption struct {
	KMS      LambdaDurableKMSOperations
	Activity IAMActivity
}

var _ lambda.DurableEncryption = LambdaDurableEncryption{}

func durableKMSCaller(ctx context.Context) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.InvokedBy = "lambda.amazonaws.com"
	metadata.SourceIP, metadata.UserAgent = "lambda.amazonaws.com", "lambda.amazonaws.com"
	return kms.WithViaService(awsctx.WithMetadata(ctx, metadata), "lambda")
}

func durableKMSService(ctx context.Context, function lambda.FunctionKey) context.Context {
	origin := awsctx.FromContext(ctx)
	return awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: function.Partition, AccountID: function.Account, Region: function.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", SourceARN: function.ARN(), Type: "AWSService"},
		InvokedBy:        "lambda.amazonaws.com", SourceIP: "lambda.amazonaws.com", UserAgent: "lambda.amazonaws.com",
	})
}

func durableKMSError(rejected *awswire.Error) *awswire.Error {
	if rejected == nil {
		return nil
	}
	out := *rejected
	switch out.Code {
	case "AccessDeniedException":
		out.Code, out.StatusCode = "KMSAccessDeniedException", 502
	case "DisabledException":
		out.Code, out.StatusCode = "KMSDisabledException", 502
	case "KMSInvalidStateException", "InvalidKeyUsageException", "InvalidCiphertextException":
		out.Code, out.StatusCode = "KMSInvalidStateException", 502
	case "NotFoundException":
		out.Code, out.StatusCode = "KMSNotFoundException", 502
	}
	return &out
}

func (a LambdaDurableEncryption) Validate(ctx context.Context, function lambda.FunctionKey, identifier string) (string, *awswire.Error) {
	parsed, err := arn.Parse(identifier)
	if err != nil || parsed.Service != "kms" || parsed.Region != function.Region || parsed.Partition != function.Partition {
		return "", &awswire.Error{Code: "InvalidParameterValueException", Message: "DurableConfig.KMSKeyArn must identify a KMS key in the function region.", StatusCode: 400}
	}
	if rejected := recordKMSActivity(ctx, a.Activity, "DescribeKey"); rejected != nil {
		return "", rejected
	}
	caller := durableKMSCaller(ctx)
	metadata, rejected := a.KMS.DescribeKey(caller, identifier)
	if rejected != nil {
		return "", durableKMSError(rejected)
	}
	if metadata.KeySpec == nil || *metadata.KeySpec != "SYMMETRIC_DEFAULT" || metadata.KeyUsage == nil || *metadata.KeyUsage != "ENCRYPT_DECRYPT" {
		return "", &awswire.Error{Code: "InvalidParameterValueException", Message: "Durable execution encryption requires a symmetric encryption KMS key.", StatusCode: 400}
	}
	key := string(*metadata.Arn)
	encryption := kmsapi.EncryptionContextType{"aws:lambda:FunctionArn": kmsapi.EncryptionContextValue(function.ARN())}
	model, _ := awscatalog.LookupService("kms")
	for _, call := range []struct {
		name  string
		input any
	}{
		{"GenerateDataKey", &kmsapi.GenerateDataKeyInput{KeyId: new(kmsapi.KeyIdType(key)), KeySpec: new(kmsapi.DataKeySpec("AES_256")), EncryptionContext: encryption, DryRun: new(kmsapi.NullableBooleanType(true))}},
		{"Decrypt", &kmsapi.DecryptInput{KeyId: new(kmsapi.KeyIdType(key)), EncryptionAlgorithm: new(kmsapi.EncryptionAlgorithmSpec("SYMMETRIC_DEFAULT")), EncryptionContext: encryption, DryRun: new(kmsapi.NullableBooleanType(true)), DryRunModifiers: kmsapi.DryRunModifierList{kmsapi.DryRunModifierTypeIGNORE_CIPHERTEXT}}},
	} {
		if rejected := recordKMSActivity(ctx, a.Activity, call.name); rejected != nil {
			return "", rejected
		}
		operation, _ := model.Operation(call.name)
		_, rejected := a.KMS.ExecuteCommand(caller, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: call.input})
		if rejected == nil {
			return "", &awswire.Error{Code: "ServiceException", Message: "KMS did not return its dry-run result.", StatusCode: 500}
		}
		if rejected.Code != "DryRunOperationException" {
			return "", durableKMSError(rejected)
		}
	}
	return key, nil
}

func (a LambdaDurableEncryption) Generate(ctx context.Context, function lambda.FunctionKey, keyARN string) ([]byte, []byte, *awswire.Error) {
	plain, wrapped, _, rejected := a.KMS.GenerateDataKey(durableKMSService(ctx, function), keyARN, map[string]string{"aws:lambda:FunctionArn": function.ARN()})
	return plain, wrapped, durableKMSError(rejected)
}

func (a LambdaDurableEncryption) Open(ctx context.Context, function lambda.FunctionKey, wrapped []byte, processing bool) ([]byte, *awswire.Error) {
	if processing {
		ctx = durableKMSService(ctx, function)
	} else {
		if rejected := recordKMSActivity(ctx, a.Activity, "Decrypt"); rejected != nil {
			return nil, rejected
		}
		ctx = durableKMSCaller(ctx)
	}
	plain, _, rejected := a.KMS.Decrypt(ctx, wrapped, map[string]string{"aws:lambda:FunctionArn": function.ARN()})
	return plain, durableKMSError(rejected)
}
