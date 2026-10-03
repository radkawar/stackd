package ebs

import (
	"context"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

// InstanceDataKeys separates caller-authorized wrapping and grant creation from
// service and identity-only infrastructure decryption. EBS owns the wrapped key
// and the returned grant IDs in its volume record; KMS owns the grants themselves.
// Grant tokens and plaintext are transient and must not be persisted.
//
// These operations join the consumer's transaction. Even on failure, Prepare may
// return a created grant and wrapped material for the consumer to retain or retire
// when committing an asynchronous launch failure. The consumer clears all returned
// plaintext after native import. Reconnecting a surviving VM must not call Decrypt.
// Stop and termination retire the infrastructure grant. The service grant remains
// until volume deletion, including termination with DeleteOnTermination enabled.
// Start creates a fresh infrastructure grant before decrypting a retained volume.
type InstanceDataKeys interface {
	PrepareInstanceVolume(context.Context, *SnapshotRecord, VolumeRecord, string) (BlockKeyMaterial, *kmsapi.CreateGrantOutput, *awswire.Error)
	// Adopt grants EBS access to an existing volume's unchanged wrapped key.
	AdoptInstanceVolume(context.Context, VolumeRecord) (*kmsapi.CreateGrantOutput, *awswire.Error)
	StartInstanceVolume(context.Context, VolumeRecord, string) (*kmsapi.CreateGrantOutput, *awswire.Error)
	DecryptInstanceVolume(context.Context, VolumeRecord, string) ([]byte, *awswire.Error)
	DecryptServiceVolume(context.Context, VolumeRecord) ([]byte, *awswire.Error)
	RetireInstanceVolumeGrant(context.Context, VolumeRecord, kmsapi.GrantIdType) *awswire.Error
}
