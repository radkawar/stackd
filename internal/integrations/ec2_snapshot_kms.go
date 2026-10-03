package integrations

import (
	"context"

	"stackd/internal/awsapi"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ebs"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
)

// EC2DiskKeys prepares snapshot and volume keys through caller-authorized KMS
// operations. Service cryptographic work uses real grants, not caller decryption.
type EC2DiskKeys struct {
	KMS            EBSKMSOperations
	Activity       IAMActivity
	Infrastructure EC2InfrastructureIdentity
}

var _ ebs.EC2DataKeys = EC2DiskKeys{}

func ec2SnapshotKMSSuffix(partition string) string {
	if partition == "aws-cn" {
		return "amazonaws.com.cn"
	}
	return "amazonaws.com"
}

func ec2SnapshotKMSRegion(ctx context.Context, scope ebs.Scope) context.Context {
	metadata := awsctx.FromContext(ctx)
	// A shared source changes the KMS region, not the requesting account or
	// session. The full key ARN selects the source owner's key.
	metadata.Partition, metadata.Region = scope.Partition, scope.Region
	return awsctx.WithMetadata(ctx, metadata)
}

func ec2SnapshotKMSCaller(ctx context.Context, invoker string) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.InvokedBy = invoker + "." + ec2SnapshotKMSSuffix(metadata.Partition)
	metadata.SourceIP, metadata.UserAgent = metadata.InvokedBy, metadata.InvokedBy
	return kms.WithViaService(awsctx.WithMetadata(ctx, metadata), "ec2")
}

func ec2SnapshotKMSService(ctx context.Context) context.Context {
	origin := awsctx.FromContext(ctx)
	return ec2DiskKMSService(ctx, "prod.kms-caller.ebs."+origin.Region+"."+ec2SnapshotKMSSuffix(origin.Partition))
}

func ec2DiskKMSService(ctx context.Context, invoker string) context.Context {
	origin := awsctx.FromContext(ctx)
	suffix := ec2SnapshotKMSSuffix(origin.Partition)
	// Preserve the transaction and causal IDs, but no caller credentials,
	// session restrictions or transport attributes authenticate this service.
	return awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: origin.Partition, AccountID: origin.AccountID, Region: origin.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "ec2." + origin.Region + "." + suffix, Type: "AWSService"},
		InvokedBy:        invoker, SourceIP: invoker, UserAgent: invoker,
	})
}

func (k EC2DiskKeys) command(ctx context.Context, name string, input any) (any, *awswire.Error) {
	// Service identities do not record caller credential activity. Forwarded
	// calls retain the real caller's action, including ReEncrypt authority.
	if !iam.IsEC2InfrastructureContext(ctx) {
		if rejected := recordKMSActivity(ctx, k.Activity, name); rejected != nil {
			return nil, rejected
		}
	}
	model, _ := awscatalog.LookupService("kms")
	operation, _ := model.Operation(name)
	return k.KMS.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
}

func (k EC2DiskKeys) DescribeKey(ctx context.Context, keyID string) (*kmsapi.KeyMetadata, *awswire.Error) {
	ctx = ec2SnapshotKMSCaller(ctx, "ec2-frontend-api")
	if rejected := recordKMSActivity(ctx, k.Activity, "DescribeKey"); rejected != nil {
		return nil, rejected
	}
	return k.KMS.DescribeKey(ctx, keyID)
}

func (k EC2DiskKeys) EnsureServiceKey(ctx context.Context, service string) (string, *awswire.Error) {
	return k.KMS.EnsureServiceKey(ec2SnapshotKMSCaller(ctx, "ec2-frontend-api"), service)
}

func (k EC2DiskKeys) PrepareCopy(ctx context.Context, source, destination ebs.SnapshotRecord, previous *ebs.SnapshotRecord) (material ebs.SnapshotCopyKeys, rejected *awswire.Error) {
	material.KMSKeyARN = destination.KMSKeyARN
	defer func() {
		if rejected == nil {
			return
		}
		work := *destination.Copy
		destination.Copy = &work
		destination.Copy.SourceGrantToken = material.SourceGrantToken
		destination.Copy.DestinationGrantToken = material.DestinationGrantToken
		destination.Copy.DestinationEncryptGrantToken = material.DestinationEncryptGrantToken
		destination.Copy.KeySource = material.KeySource
		if failure := k.RetireCopy(ctx, destination); failure != nil {
			rejected = failure
		}
	}()
	if destination.KMSKeyARN != "" {
		if previous != nil {
			material.KeySource = previous.Key
			material.DestinationGrantToken, rejected = k.copyGrant(ctx, *previous, "Decrypt", "prod.kms-caller.ebs."+previous.Key.Region)
			if rejected != nil {
				return material, rejected
			}
			material.DestinationEncryptGrantToken, rejected = k.copyGrant(ctx, destination, "Encrypt", "ec2-frontend-api")
			if rejected != nil {
				return material, rejected
			}
			if previous.Key == source.Key {
				material.SourceGrantToken = material.DestinationGrantToken
			}
		} else {
			material.KeySource = destination.Key
			destinationContext := ec2SnapshotKMSRegion(ctx, destination.Key.Scope)
			id, size := kmsapi.KeyIdType(destination.KMSKeyARN), kmsapi.NumberOfBytesType(64)
			output, failure := k.command(ec2SnapshotKMSCaller(destinationContext, "ec2-frontend-api"), "GenerateDataKeyWithoutPlaintext", &kmsapi.GenerateDataKeyWithoutPlaintextInput{
				KeyId: &id, NumberOfBytes: &size,
				EncryptionContext: kmsapi.EncryptionContextType{"aws:ebs:id": kmsapi.EncryptionContextValue(destination.Key.ID)},
			})
			if failure != nil {
				return material, failure
			}
			generated := output.(*kmsapi.GenerateDataKeyWithoutPlaintextOutput)
			material.WrappedKey, material.KMSKeyARN = generated.CiphertextBlob, string(*generated.KeyId)
			material.DestinationGrantToken, rejected = k.copyGrant(ctx, destination, "Decrypt", "ec2-frontend-api")
			if rejected != nil {
				return material, rejected
			}
		}
	}
	if source.KMSKeyARN != "" && material.SourceGrantToken == "" {
		material.SourceGrantToken, rejected = k.copyGrant(ctx, source, "Decrypt", "prod.kms-caller.ebs."+source.Key.Region)
	}
	return material, rejected
}

func (k EC2DiskKeys) copyGrant(ctx context.Context, snapshot ebs.SnapshotRecord, operation kmsapi.GrantOperation, invoker string) (string, *awswire.Error) {
	encryption := kmsapi.EncryptionContextType{"aws:ebs:id": kmsapi.EncryptionContextValue(snapshot.EncryptionContextID())}
	token, rejected := k.createDiskGrant(ec2SnapshotKMSRegion(ctx, snapshot.Key.Scope), snapshot.KMSKeyARN, &kmsapi.GrantConstraints{EncryptionContextEquals: encryption}, operation, invoker)
	if rejected != nil {
		return "", rejected
	}
	return string(*token), nil
}

func (k EC2DiskKeys) ResumeCopy(ctx context.Context, source, destination, keySource ebs.SnapshotRecord) (material ebs.BlockKeyMaterial, rejected *awswire.Error) {
	material.WrappedKey, material.KMSKeyARN = destination.WrappedKey, destination.KMSKeyARN
	if destination.KMSKeyARN != "" {
		material.DestinationPlaintext, rejected = k.decryptCopyGrant(ctx, keySource, destination.Copy.DestinationGrantToken)
		if rejected != nil {
			return material, rejected
		}
		if destination.Copy.DestinationEncryptGrantToken != "" && len(destination.WrappedKey) == 0 {
			id := kmsapi.KeyIdType(destination.KMSKeyARN)
			service := ec2SnapshotKMSService(ec2SnapshotKMSRegion(ctx, destination.Key.Scope))
			output, failure := k.command(service, "Encrypt", &kmsapi.EncryptInput{
				KeyId: &id, Plaintext: material.DestinationPlaintext,
				EncryptionContext: kmsapi.EncryptionContextType{"aws:ebs:id": kmsapi.EncryptionContextValue(destination.Key.ID)},
				GrantTokens:       kmsapi.GrantTokenList{kmsapi.GrantTokenType(destination.Copy.DestinationEncryptGrantToken)},
			})
			if failure != nil {
				return material, failure
			}
			encrypted := output.(*kmsapi.EncryptOutput)
			material.WrappedKey, material.KMSKeyARN = encrypted.CiphertextBlob, string(*encrypted.KeyId)
		}
	}
	if source.KMSKeyARN != "" {
		if destination.Copy.SourceGrantToken == destination.Copy.DestinationGrantToken {
			material.SourcePlaintext = material.DestinationPlaintext
		} else {
			material.SourcePlaintext, rejected = k.decryptCopyGrant(ctx, source, destination.Copy.SourceGrantToken)
		}
	}
	return material, rejected
}

func (k EC2DiskKeys) decryptCopyGrant(ctx context.Context, snapshot ebs.SnapshotRecord, token string) ([]byte, *awswire.Error) {
	id := kmsapi.KeyIdType(snapshot.KMSKeyARN)
	service := ec2SnapshotKMSService(ec2SnapshotKMSRegion(ctx, snapshot.Key.Scope))
	output, rejected := k.command(service, "Decrypt", &kmsapi.DecryptInput{
		KeyId: &id, CiphertextBlob: snapshot.WrappedKey,
		EncryptionContext: kmsapi.EncryptionContextType{"aws:ebs:id": kmsapi.EncryptionContextValue(snapshot.EncryptionContextID())},
		GrantTokens:       kmsapi.GrantTokenList{kmsapi.GrantTokenType(token)},
	})
	if rejected != nil {
		return nil, rejected
	}
	return output.(*kmsapi.DecryptOutput).Plaintext, nil
}

func (k EC2DiskKeys) RetireCopy(ctx context.Context, destination ebs.SnapshotRecord) *awswire.Error {
	work := destination.Copy
	sourceToken := work.SourceGrantToken
	if sourceToken == work.DestinationGrantToken {
		sourceToken = ""
	}
	for _, grant := range []struct {
		token string
		scope ebs.Scope
	}{
		{work.DestinationGrantToken, work.KeySource.Scope},
		{work.DestinationEncryptGrantToken, destination.Key.Scope},
		{sourceToken, work.Source.Scope},
	} {
		if grant.token == "" {
			continue
		}
		token := kmsapi.GrantTokenType(grant.token)
		service := ec2SnapshotKMSService(ec2SnapshotKMSRegion(ctx, grant.scope))
		// These are service-issued tokens retained at admission. If their
		// grants were revoked, no authority remains for cleanup to retire.
		if _, rejected := k.command(service, "RetireGrant", &kmsapi.RetireGrantInput{GrantToken: &token}); rejected != nil && rejected.Code != "InvalidGrantTokenException" {
			return rejected
		}
	}
	return nil
}

func (k EC2DiskKeys) createDiskGrant(ctx context.Context, keyARN string, constraints *kmsapi.GrantConstraints, operation kmsapi.GrantOperation, invoker string) (*kmsapi.GrantTokenType, *awswire.Error) {
	principal := ec2DiskGrantPrincipal(ctx)
	output, rejected := k.createDiskGrantFor(ctx, keyARN, principal, constraints, operation, invoker)
	if rejected != nil {
		return nil, rejected
	}
	return output.GrantToken, nil
}

func ec2DiskGrantPrincipal(ctx context.Context) kmsapi.PrincipalIdType {
	metadata := awsctx.FromContext(ctx)
	return kmsapi.PrincipalIdType("ec2." + metadata.Region + "." + ec2SnapshotKMSSuffix(metadata.Partition))
}

func (k EC2DiskKeys) createDiskGrantFor(ctx context.Context, keyARN string, grantee kmsapi.PrincipalIdType, constraints *kmsapi.GrantConstraints, operation kmsapi.GrantOperation, invoker string) (*kmsapi.CreateGrantOutput, *awswire.Error) {
	principal := ec2DiskGrantPrincipal(ctx)
	id := kmsapi.KeyIdType(keyARN)
	caller := kms.WithAWSResourceGrant(ec2SnapshotKMSCaller(ctx, invoker))
	output, rejected := k.command(caller, "CreateGrant", &kmsapi.CreateGrantInput{
		KeyId: &id, GranteePrincipal: &grantee, RetiringPrincipal: &principal,
		Operations:  kmsapi.GrantOperationList{operation},
		Constraints: constraints,
	})
	if rejected != nil {
		return nil, rejected
	}
	return output.(*kmsapi.CreateGrantOutput), nil
}
