// Package ebs exposes service-owned EBS snapshot storage contracts.
package ebs

import (
	domain "stackd/internal/services/ebs"
	"stackd/storage/memory"
)

type (
	Repository            = domain.Repository
	Reader                = domain.Reader
	Transaction           = domain.Transaction
	Scope                 = domain.Scope
	SnapshotKey           = domain.SnapshotKey
	SnapshotRecord        = domain.SnapshotRecord
	SnapshotCopy          = domain.SnapshotCopy
	SnapshotVolume        = domain.SnapshotVolume
	VolumeKey             = domain.VolumeKey
	VolumeRecord          = domain.VolumeRecord
	VolumeCreation        = domain.VolumeCreation
	VolumeConfiguration   = domain.VolumeConfiguration
	VolumeModification    = domain.VolumeModification
	VolumeBlockKey        = domain.VolumeBlockKey
	VolumeBlockInfo       = domain.VolumeBlockInfo
	VolumeBlockRecord     = domain.VolumeBlockRecord
	SnapshotCounts        = domain.SnapshotCounts
	SnapshotShare         = domain.SnapshotShare
	SnapshotTag           = domain.SnapshotTag
	SnapshotPublicAccess  = domain.SnapshotPublicAccess
	SharedTagsKey         = domain.SharedTagsKey
	BlockKey              = domain.BlockKey
	BlockInfo             = domain.BlockInfo
	BlockRecord           = domain.BlockRecord
	BlockEncryptionOrigin = domain.BlockEncryptionOrigin
	EncryptionDefault     = domain.EncryptionDefault
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }

// SnapshotID deterministically names a snapshot from its scoped durable sequence.
func SnapshotID(scope Scope, sequence uint64) string { return domain.SnapshotID(scope, sequence) }

// VolumeID deterministically names a volume from the same scoped durable sequence.
func VolumeID(scope Scope, sequence uint64) string { return domain.VolumeID(scope, sequence) }
