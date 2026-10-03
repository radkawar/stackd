package integrations

import (
	"context"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ebs"
)

// EC2InfrastructureIdentity is IAM's internal, credential-free identity-only
// authority. The returned actor is an assumed role, not an SCP-exempt service or
// the guest instance-profile role. Its only KMS permissions come from real grants
// and applicable key policies, subject to ordinary organization controls.
type EC2InfrastructureIdentity interface {
	EC2InfrastructureContext(context.Context, string) (context.Context, error)
}

var _ ebs.InstanceDataKeys = EC2DiskKeys{}

func (k EC2DiskKeys) PrepareInstanceVolume(ctx context.Context, source *ebs.SnapshotRecord, destination ebs.VolumeRecord, keyID string) (ebs.BlockKeyMaterial, *kmsapi.CreateGrantOutput, *awswire.Error) {
	return k.prepareVolume(ctx, source, destination, keyID, true)
}

// AdoptInstanceVolume retains an EBS service grant when a standalone encrypted
// volume is attached. Its existing key and encrypted bytes remain unchanged;
// admission needs CreateGrant, never caller Decrypt or a replacement data key.
func (k EC2DiskKeys) AdoptInstanceVolume(ctx context.Context, volume ebs.VolumeRecord) (*kmsapi.CreateGrantOutput, *awswire.Error) {
	if !volume.Encrypted {
		return nil, nil
	}
	ctx = ec2SnapshotKMSRegion(ctx, volume.Key.Scope)
	return k.createDiskGrantFor(ctx, volume.KMSKeyARN, ec2DiskGrantPrincipal(ctx),
		&kmsapi.GrantConstraints{EncryptionContextSubset: instanceVolumeEncryptionContext(volume)}, "Decrypt", "ec2-frontend-api")
}

// StartInstanceVolume creates the native instance-session grant as the launcher,
// including on a restart after Stop retired the previous infrastructure grant.
// It performs no unwrap: that is only required when creating a native process.
func (k EC2DiskKeys) StartInstanceVolume(ctx context.Context, volume ebs.VolumeRecord, instanceID string) (*kmsapi.CreateGrantOutput, *awswire.Error) {
	if !volume.Encrypted {
		return nil, nil
	}
	ctx = ec2SnapshotKMSRegion(ctx, volume.Key.Scope)
	infrastructure, rejected := k.instanceInfrastructureContext(ctx, instanceID)
	if rejected != nil {
		return nil, rejected
	}
	grantee := kmsapi.PrincipalIdType(awsctx.FromContext(infrastructure).PrincipalARN)
	return k.createDiskGrantFor(ctx, volume.KMSKeyARN, grantee,
		&kmsapi.GrantConstraints{EncryptionContextSubset: instanceVolumeEncryptionContext(volume)}, "Decrypt", "ec2-frontend-api")
}

// DecryptInstanceVolume is used only for a new native VM or native disk import.
// A surviving VM reconnects with its already-loaded secret, without this call.
func (k EC2DiskKeys) DecryptInstanceVolume(ctx context.Context, volume ebs.VolumeRecord, instanceID string) ([]byte, *awswire.Error) {
	if !volume.Encrypted {
		return nil, nil
	}
	ctx = ec2SnapshotKMSRegion(ctx, volume.Key.Scope)
	infrastructure, rejected := k.instanceInfrastructureContext(ctx, instanceID)
	if rejected != nil {
		return nil, rejected
	}
	return k.decryptVolumeKey(infrastructure, volume.WrappedKey, instanceVolumeEncryptionContext(volume), nil)
}

// DecryptServiceVolume consumes the retained EBS service grant for volume bytes,
// including snapshot materialization while an encrypted instance is stopped.
// The initiating user's Decrypt permission does not authenticate the EBS actor.
func (k EC2DiskKeys) DecryptServiceVolume(ctx context.Context, volume ebs.VolumeRecord) ([]byte, *awswire.Error) {
	if !volume.Encrypted {
		return nil, nil
	}
	ctx = ec2SnapshotKMSRegion(ctx, volume.Key.Scope)
	service := ec2DiskKMSService(ctx, "ebs."+ec2SnapshotKMSSuffix(volume.Key.Partition))
	return k.decryptVolumeKey(service, volume.WrappedKey, instanceVolumeEncryptionContext(volume), nil)
}

func (k EC2DiskKeys) RetireInstanceVolumeGrant(ctx context.Context, volume ebs.VolumeRecord, grantID kmsapi.GrantIdType) *awswire.Error {
	if grantID == "" {
		return nil
	}
	ctx = ec2SnapshotKMSRegion(ctx, volume.Key.Scope)
	retiring := ec2DiskKMSService(ctx, "AWS Internal")
	_, rejected := k.command(retiring, "RetireGrant", &kmsapi.RetireGrantInput{KeyId: new(kmsapi.KeyIdType(volume.KMSKeyARN)), GrantId: &grantID})
	// A revoked retained grant (or its deleted key) is already gone. Keep
	// authorization and storage failures visible to the owning lifecycle.
	if rejected != nil && rejected.Code == "NotFoundException" {
		return nil
	}
	return rejected
}

func (k EC2DiskKeys) instanceInfrastructureContext(ctx context.Context, instanceID string) (context.Context, *awswire.Error) {
	if k.Infrastructure == nil {
		return nil, &awswire.Error{Code: "KMSInternalException", Message: "EC2 infrastructure identity authority is not configured.", StatusCode: 500}
	}
	infrastructure, err := k.Infrastructure.EC2InfrastructureContext(ctx, instanceID)
	if err != nil {
		return nil, serviceRoleFailure(err)
	}
	return infrastructure, nil
}

func instanceVolumeEncryptionContext(volume ebs.VolumeRecord) kmsapi.EncryptionContextType {
	return kmsapi.EncryptionContextType{"aws:ebs:id": kmsapi.EncryptionContextValue(volume.Key.ID)}
}
