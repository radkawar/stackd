package ebs

import (
	"context"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

// EC2DataKeys separates EC2's forwarded caller and service-grant operations from
// direct EBS callers' data-key permissions. Records own source encryption context.
// An absent source requests a new empty volume; a non-nil previous snapshot
// identifies the retained data key selected for an incremental snapshot copy.
type EC2DataKeys interface {
	DescribeKey(context.Context, string) (*kmsapi.KeyMetadata, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
	PrepareCopy(context.Context, SnapshotRecord, SnapshotRecord, *SnapshotRecord) (SnapshotCopyKeys, *awswire.Error)
	ResumeCopy(context.Context, SnapshotRecord, SnapshotRecord, SnapshotRecord) (BlockKeyMaterial, *awswire.Error)
	RetireCopy(context.Context, SnapshotRecord) *awswire.Error
	PrepareVolume(context.Context, *SnapshotRecord, VolumeRecord, string) (BlockKeyMaterial, *awswire.Error)
	ResumeVolume(context.Context, VolumeRecord) (BlockKeyMaterial, *awswire.Error)
	RetireVolumeCreationGrant(context.Context, VolumeRecord) *awswire.Error
}

// BlockKeyMaterial contains only the keys needed while copying blocks. The caller
// must clear both plaintext slices after use; they may share storage when source
// and destination reuse a data key. Only wrapped keys, KMS key ARN and service
// grant identity may be retained by pending resource creation.
type BlockKeyMaterial struct {
	SourcePlaintext, DestinationPlaintext, WrappedKey []byte
	KMSKeyARN                                         string
	SourceWrappedKey                                  []byte
	ServiceGrantID                                    kmsapi.GrantIdType
	// ReuseSourceCiphertext preserves encrypted blocks when native ReEncrypt
	// rewraps their data key without requiring plaintext or a service grant.
	ReuseSourceCiphertext bool
}
