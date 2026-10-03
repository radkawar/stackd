package integrations

import (
	"context"
	"strings"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
	"stackd/internal/services/ebs"
)

// PrepareVolume resolves the selected key through the cryptographic operation
// itself. DescribeKey is not an additional caller permission for volume creation.
func (k EC2DiskKeys) PrepareVolume(ctx context.Context, source *ebs.SnapshotRecord, destination ebs.VolumeRecord, keyID string) (ebs.BlockKeyMaterial, *awswire.Error) {
	material, _, rejected := k.prepareVolume(ctx, source, destination, keyID, false)
	return material, rejected
}

// prepareVolume admits wrapping and the real destination service grant. Source
// payload decryption waits for hydration; empty-volume and ciphertext-reuse
// preparation retain their existing KMS operations.
func (k EC2DiskKeys) prepareVolume(ctx context.Context, source *ebs.SnapshotRecord, destination ebs.VolumeRecord, keyID string, retainGrant bool) (ebs.BlockKeyMaterial, *kmsapi.CreateGrantOutput, *awswire.Error) {
	var material ebs.BlockKeyMaterial
	if !destination.Encrypted {
		return material, nil, nil
	}
	material.KMSKeyARN = destination.KMSKeyARN
	if material.KMSKeyARN == "" && strings.HasPrefix(keyID, "arn:") && strings.Contains(keyID, ":key/") {
		material.KMSKeyARN = keyID
	}
	ctx = ec2SnapshotKMSRegion(ctx, destination.Key.Scope)
	caller := ec2SnapshotKMSCaller(ctx, "ec2-frontend-api")
	encryption := kmsapi.EncryptionContextType{"aws:ebs:id": kmsapi.EncryptionContextValue(destination.Key.ID)}
	id := kmsapi.KeyIdType(keyID)
	var sourceWrapped []byte
	if source != nil && source.KMSKeyARN != "" {
		output, rejected := k.command(caller, "ReEncrypt", &kmsapi.ReEncryptInput{
			CiphertextBlob: source.WrappedKey, DestinationKeyId: &id,
			SourceEncryptionContext:      kmsapi.EncryptionContextType{"aws:ebs:id": kmsapi.EncryptionContextValue(source.EncryptionContextID())},
			DestinationEncryptionContext: encryption,
		})
		if rejected != nil {
			return ebs.BlockKeyMaterial{KMSKeyARN: material.KMSKeyARN}, nil, rejected
		}
		rewrapped := output.(*kmsapi.ReEncryptOutput)
		material.KMSKeyARN = string(*rewrapped.KeyId)
		if source.Key.AccountID == destination.Key.AccountID && *rewrapped.SourceKeyId == *rewrapped.KeyId {
			// An owned source rewraps its existing data key. Standalone
			// hydration preserves ciphertext without an additional grant;
			// native instance use still needs the retained service grant.
			material.WrappedKey = rewrapped.CiphertextBlob
			material.ReuseSourceCiphertext = true
			if !retainGrant {
				return material, nil, nil
			}
		}
		if !material.ReuseSourceCiphertext {
			sourceWrapped = rewrapped.CiphertextBlob
		}
	}
	if !material.ReuseSourceCiphertext {
		size := kmsapi.NumberOfBytesType(64)
		output, rejected := k.command(caller, "GenerateDataKeyWithoutPlaintext", &kmsapi.GenerateDataKeyWithoutPlaintextInput{
			KeyId: &id, NumberOfBytes: &size, EncryptionContext: encryption,
		})
		if rejected != nil {
			return ebs.BlockKeyMaterial{KMSKeyARN: material.KMSKeyARN}, nil, rejected
		}
		generated := output.(*kmsapi.GenerateDataKeyWithoutPlaintextOutput)
		material.WrappedKey, material.KMSKeyARN = generated.CiphertextBlob, string(*generated.KeyId)
	}
	grant, rejected := k.createDiskGrantFor(ctx, material.KMSKeyARN, ec2DiskGrantPrincipal(ctx),
		&kmsapi.GrantConstraints{EncryptionContextSubset: encryption}, "Decrypt", "ec2-frontend-api")
	if rejected != nil {
		if !retainGrant {
			return ebs.BlockKeyMaterial{KMSKeyARN: material.KMSKeyARN}, nil, rejected
		}
		return material, nil, rejected
	}
	if source != nil && !material.ReuseSourceCiphertext {
		material.SourceWrappedKey = sourceWrapped
		material.ServiceGrantID = *grant.GrantId
		return material, grant, nil
	}
	service := ec2DiskKMSService(ctx, "ebs."+ec2SnapshotKMSSuffix(destination.Key.Partition))
	material.DestinationPlaintext, rejected = k.decryptVolumeKey(service, material.WrappedKey, encryption, grant.GrantToken)
	if !retainGrant {
		retirement := ec2DiskKMSService(ctx, "AWS Internal")
		_, retireError := k.command(retirement, "RetireGrant", &kmsapi.RetireGrantInput{GrantToken: grant.GrantToken})
		if rejected == nil {
			rejected = retireError
		}
		grant = nil
	}
	if rejected != nil {
		clear(material.SourcePlaintext)
		clear(material.DestinationPlaintext)
		material.SourcePlaintext, material.DestinationPlaintext = nil, nil
		if !retainGrant {
			return ebs.BlockKeyMaterial{KMSKeyARN: material.KMSKeyARN}, nil, rejected
		}
		return material, grant, rejected
	}
	return material, grant, nil
}

// ResumeVolume unwraps admitted keys using only the retained destination grant.
// The source key was rewrapped at admission: source deletion, sharing changes,
// and source-account KMS policy changes are not new authorization decisions.
func (k EC2DiskKeys) ResumeVolume(ctx context.Context, volume ebs.VolumeRecord) (ebs.BlockKeyMaterial, *awswire.Error) {
	var material ebs.BlockKeyMaterial
	if !volume.Encrypted || volume.Creation == nil || volume.Creation.ReuseSourceCiphertext {
		return material, nil
	}
	ctx = ec2SnapshotKMSRegion(ctx, volume.Key.Scope)
	service := ec2DiskKMSService(ctx, "ebs."+ec2SnapshotKMSSuffix(volume.Key.Partition))
	encryption := instanceVolumeEncryptionContext(volume)
	var rejected *awswire.Error
	material.DestinationPlaintext, rejected = k.decryptVolumeKey(service, volume.WrappedKey, encryption, nil)
	if rejected == nil && len(volume.Creation.SourceWrappedKey) != 0 {
		material.SourcePlaintext, rejected = k.decryptVolumeKey(service, volume.Creation.SourceWrappedKey, encryption, nil)
	}
	if rejected != nil {
		clear(material.SourcePlaintext)
		clear(material.DestinationPlaintext)
		material.SourcePlaintext, material.DestinationPlaintext = nil, nil
	}
	return material, rejected
}

func (k EC2DiskKeys) RetireVolumeCreationGrant(ctx context.Context, volume ebs.VolumeRecord) *awswire.Error {
	return k.RetireInstanceVolumeGrant(ctx, volume, volume.ServiceGrantID)
}

func (k EC2DiskKeys) decryptVolumeKey(ctx context.Context, wrapped []byte, encryption kmsapi.EncryptionContextType, token *kmsapi.GrantTokenType) ([]byte, *awswire.Error) {
	input := &kmsapi.DecryptInput{CiphertextBlob: wrapped, EncryptionContext: encryption}
	if token != nil {
		input.GrantTokens = kmsapi.GrantTokenList{*token}
	}
	output, rejected := k.command(ctx, "Decrypt", input)
	if rejected != nil {
		return nil, rejected
	}
	return output.(*kmsapi.DecryptOutput).Plaintext, nil
}
