package integrations

import (
	"context"
	"strings"

	"stackd/internal/awsapi"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ecr"
	"stackd/internal/services/kms"
)

// ECRKMSOperations is implemented by the existing KMS owner. Every command
// evaluates current key state, policies and grants and joins ctx's transaction.
type ECRKMSOperations interface {
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
	DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}

// ECRKeys separates caller-authorized provisioning/retirement from repository
// service cryptography. It does not issue credentials or retain any key material.
// Provision and Retire must run inside the ECR repository transaction so grant
// changes, resource state and API events either commit or roll back together.
type ECRKeys struct {
	KMS      ECRKMSOperations
	Activity IAMActivity
}

var _ ecr.DataKeys = ECRKeys{}

func ecrKMSRepositoryARN(key ecr.RepositoryKey) string {
	return "arn:" + key.Partition + ":ecr:" + key.Region + ":" + key.AccountID + ":repository/" + key.Name
}

func ecrKMSPrincipal(key ecr.RepositoryKey) string {
	suffix := "amazonaws.com"
	if key.Partition == "aws-cn" {
		suffix += ".cn"
	}
	return "ecr." + key.Region + "." + suffix
}

func ecrKMSCaller(ctx context.Context, key ecr.RepositoryKey) context.Context {
	m := awsctx.FromContext(ctx)
	m.Partition, m.Region = key.Partition, key.Region
	// AWS's ECR CreateGrant example retains the caller's credentials and
	// source address. The audit invoker does not replace the IAM principal.
	m.InvokedBy = "AWS Internal"
	return kms.WithViaService(awsctx.WithMetadata(ctx, m), "ecr")
}

func ecrKMSService(ctx context.Context, key ecr.RepositoryKey) context.Context {
	origin := awsctx.FromContext(ctx)
	principal := ecrKMSPrincipal(key)
	return awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: principal, SourceARN: ecrKMSRepositoryARN(key), Type: "AWSService"},
		InvokedBy:        principal, SourceIP: principal, UserAgent: principal,
	})
}

func ecrKMSEncryptionContext(key ecr.RepositoryKey) kmsapi.EncryptionContextType {
	// There is no service-owned S3 bucket in this local data plane. Bind the
	// real repository, not an invented S3 ARN or a second backing-object store.
	return kmsapi.EncryptionContextType{"aws:ecr:arn": kmsapi.EncryptionContextValue(ecrKMSRepositoryARN(key))}
}

func ecrKMSPayloadContext(key ecr.RepositoryKey, identity string) kmsapi.EncryptionContextType {
	encryption := ecrKMSEncryptionContext(key)
	// The private storage object's identity is genuine local context, not
	// the ARN of an S3 bucket that this data plane does not own.
	encryption["stackd:ecr:object"] = kmsapi.EncryptionContextValue(identity)
	return encryption
}

func ecrKMSInvalid(code, message string) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: 400}
}

func (k ECRKeys) command(ctx context.Context, name string, input any) (any, *awswire.Error) {
	if rejected := recordKMSActivity(ctx, k.Activity, name); rejected != nil {
		return nil, rejected
	}
	model, _ := awscatalog.LookupService("kms")
	operation, _ := model.Operation(name)
	return k.KMS.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
}

func (k ECRKeys) Provision(ctx context.Context, repository ecr.RepositoryKey, keyID string) (ecr.KeyMaterial, *awswire.Error) {
	caller := ecrKMSCaller(ctx, repository)
	defaultAlias := "arn:" + repository.Partition + ":kms:" + repository.Region + ":" + repository.AccountID + ":alias/aws/ecr"
	if keyID == "" || keyID == "alias/aws/ecr" || keyID == defaultAlias {
		keyID = defaultAlias
		if awsctx.FromContext(ctx).AccountID == repository.AccountID {
			var rejected *awswire.Error
			keyID, rejected = k.KMS.EnsureServiceKey(caller, "ecr")
			if rejected != nil {
				return ecr.KeyMaterial{}, rejected
			}
		}
	}
	if rejected := recordKMSActivity(caller, k.Activity, "DescribeKey"); rejected != nil {
		return ecr.KeyMaterial{}, rejected
	}
	metadata, rejected := k.KMS.DescribeKey(caller, keyID)
	if rejected != nil {
		return ecr.KeyMaterial{}, rejected
	}
	if metadata == nil || metadata.Arn == nil || metadata.KeySpec == nil || string(*metadata.KeySpec) != "SYMMETRIC_DEFAULT" || metadata.KeyUsage == nil || string(*metadata.KeyUsage) != "ENCRYPT_DECRYPT" {
		return ecr.KeyMaterial{}, ecrKMSInvalid("InvalidKeyUsageException", "ECR requires a symmetric KMS encryption key.")
	}
	if metadata.KeyState != nil && string(*metadata.KeyState) == "Disabled" {
		return ecr.KeyMaterial{}, ecrKMSInvalid("DisabledException", "The KMS key is disabled.")
	}
	if metadata.KeyState == nil || string(*metadata.KeyState) != "Enabled" {
		return ecr.KeyMaterial{}, ecrKMSInvalid("KMSInvalidStateException", "The KMS key is not enabled for encryption.")
	}
	arn := string(*metadata.Arn)
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != repository.Partition || parts[2] != "kms" || parts[3] != repository.Region || parts[4] == "" || !strings.HasPrefix(parts[5], "key/") {
		return ecr.KeyMaterial{}, ecrKMSInvalid("NotFoundException", "The KMS key must be in the repository's Region and partition.")
	}

	material := ecr.KeyMaterial{KeyID: arn, Grants: make([]string, 0, 2), GrantTokens: make([]string, 0, 2)}
	id := kmsapi.KeyIdType(arn)
	principal := kmsapi.PrincipalIdType(ecrKMSPrincipal(repository))
	grantCaller := kms.WithAWSResourceGrant(caller)
	// Native ECR creates two unnamed grants, each with both operations and
	// the same repository subset constraint. Their identities remain distinct.
	// https://docs.aws.amazon.com/AmazonECR/latest/userguide/logging-using-cloudtrail.html#cloudtrail-examples-create-repository-kms
	for range 2 {
		output, rejected := k.command(grantCaller, "CreateGrant", &kmsapi.CreateGrantInput{
			KeyId: &id, GranteePrincipal: &principal, RetiringPrincipal: &principal,
			Operations:  kmsapi.GrantOperationList{"Decrypt", "GenerateDataKey"},
			Constraints: &kmsapi.GrantConstraints{EncryptionContextSubset: ecrKMSEncryptionContext(repository)},
		})
		if rejected != nil {
			return ecr.KeyMaterial{}, rejected
		}
		grant := output.(*kmsapi.CreateGrantOutput)
		material.Grants = append(material.Grants, string(*grant.GrantId))
		material.GrantTokens = append(material.GrantTokens, string(*grant.GrantToken))
	}
	return material, nil
}

func ecrKMSGrantTokens(tokens []string) kmsapi.GrantTokenList {
	result := make(kmsapi.GrantTokenList, len(tokens))
	for index, token := range tokens {
		result[index] = kmsapi.GrantTokenType(token)
	}
	return result
}

func (k ECRKeys) Generate(ctx context.Context, repository ecr.RepositoryRecord, identity string) (ecr.KeyMaterial, *awswire.Error) {
	if repository.KMSKeyID == "" || len(repository.Grants) != 2 || len(repository.GrantTokens) != 2 {
		return ecr.KeyMaterial{}, ecrKMSInvalid("KMSInvalidStateException", "The repository has no valid KMS key and grants.")
	}
	output, rejected := k.command(ecrKMSService(ctx, repository.Key), "GenerateDataKey", &kmsapi.GenerateDataKeyInput{
		KeyId: new(kmsapi.KeyIdType(repository.KMSKeyID)), KeySpec: new(kmsapi.DataKeySpec("AES_256")),
		EncryptionContext: ecrKMSPayloadContext(repository.Key, identity), GrantTokens: ecrKMSGrantTokens(repository.GrantTokens),
	})
	if rejected != nil {
		return ecr.KeyMaterial{}, rejected
	}
	generated := output.(*kmsapi.GenerateDataKeyOutput)
	return ecr.KeyMaterial{KeyID: string(*generated.KeyId), Plaintext: generated.Plaintext, Wrapped: generated.CiphertextBlob}, nil
}

func (k ECRKeys) Decrypt(ctx context.Context, repository ecr.RepositoryRecord, identity string, wrapped []byte) ([]byte, *awswire.Error) {
	if repository.KMSKeyID == "" || len(wrapped) == 0 || len(repository.Grants) != 2 || len(repository.GrantTokens) != 2 {
		return nil, ecrKMSInvalid("KMSInvalidStateException", "The repository has no valid KMS key and grants.")
	}
	output, rejected := k.command(ecrKMSService(ctx, repository.Key), "Decrypt", &kmsapi.DecryptInput{
		KeyId: new(kmsapi.KeyIdType(repository.KMSKeyID)), CiphertextBlob: wrapped,
		EncryptionContext: ecrKMSPayloadContext(repository.Key, identity), GrantTokens: ecrKMSGrantTokens(repository.GrantTokens),
	})
	if rejected != nil {
		return nil, rejected
	}
	return output.(*kmsapi.DecryptOutput).Plaintext, nil
}

func (k ECRKeys) Retire(ctx context.Context, repository ecr.RepositoryRecord) *awswire.Error {
	caller := ecrKMSCaller(ctx, repository.Key)
	id := kmsapi.KeyIdType(repository.KMSKeyID)
	for _, grant := range repository.Grants {
		_, rejected := k.command(caller, "RetireGrant", &kmsapi.RetireGrantInput{KeyId: &id, GrantId: new(kmsapi.GrantIdType(grant))})
		if rejected != nil && rejected.Code != "NotFoundException" {
			return rejected
		}
		// A previously revoked or retired grant has nothing left to retire.
	}
	return nil
}
