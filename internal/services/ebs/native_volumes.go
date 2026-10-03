package ebs

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/ec2"
)

// NativeDisks owns real independent qcow2 disks. Disk keys are transient; every
// native operation runs outside repository transactions.
type NativeDisks interface {
	CreateDisk(context.Context, native.Disk, int64) error
	WriteDisk(context.Context, native.Disk, func(io.WriterAt) error) error
	ReadDisk(context.Context, native.Disk, func(io.ReaderAt) error) error
	Allocated(context.Context, native.Disk) ([]native.Extent, error)
	Backup(context.Context, native.Disk, native.Disk) (native.BackupResult, error)
	BackupDisks(context.Context, []native.Disk, []native.Disk) ([]native.BackupResult, error)
	CheckResizeDisk(context.Context, native.Disk, int64) error
	ResizeDisk(context.Context, native.Disk, int64) error
	DeleteDisk(context.Context, native.Disk) error
}

// InstanceAttachments projects the EC2-owned block-device mapping, including
// stopped instances. EBS never persists a second relationship.
type InstanceAttachments interface {
	InstanceVolumeAttachments(context.Context, ec2.ResourceKey) ([]ec2.InstanceVolumeAttachmentRecord, error)
}

func (s *Service) volumeAttachments(ctx context.Context, v VolumeRecord) (api.VolumeAttachmentList, error) {
	out := api.VolumeAttachmentList{}
	if s.attachments == nil {
		return out, nil
	}
	rows, err := s.attachments.InstanceVolumeAttachments(ctx, ec2.ResourceKey{Scope: ec2.Scope{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region}, ID: v.Key.ID})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		e := row.Mapping.Ebs
		if e == nil || value(e.Status) == "detached" {
			continue
		}
		out = append(out, api.VolumeAttachment{VolumeId: new(api.String(v.Key.ID)), InstanceId: new(api.String(row.InstanceKey.ID)), Device: row.Mapping.DeviceName, AttachTime: e.AttachTime, DeleteOnTermination: e.DeleteOnTermination, EbsCardIndex: e.EbsCardIndex, State: new(api.VolumeAttachmentState(value(e.Status)))})
	}
	return out, nil
}

func nativeVolumeDisk(v VolumeRecord) native.Disk {
	return native.Disk{ID: volumeARN(v.Key), Path: v.NativePath, Encrypted: v.Encrypted}
}

func (s *Service) volumeNativePath(v VolumeRecord) (string, error) {
	if s.nativeDisks == nil || !filepath.IsAbs(s.nativeVolumeDirectory) {
		return "", errors.New("native EBS disk storage is not configured")
	}
	digest := sha256.Sum256([]byte(volumeARN(v.Key)))
	return filepath.Join(s.nativeVolumeDirectory, hex.EncodeToString(digest[:])+".qcow2"), nil
}

// hydrateNativeVolume is called under nativeWorkMu. A crash before the authority
// commit leaves only a reconstructible unbound file at the resource-owned path.
// Recovery removes it and reimports retained encrypted blocks from the beginning.
func (s *Service) hydrateNativeVolume(ctx context.Context, v VolumeRecord, key []byte) (native.Disk, error) {
	if v.Creation != nil || v.StateMessage != "" {
		return native.Disk{}, errors.New("volume contents are not ready for native hydration")
	}
	disk := nativeVolumeDisk(v)
	disk.Key = key
	if disk.Path != "" {
		return disk, nil
	}
	path, err := s.volumeNativePath(v)
	if err != nil {
		return native.Disk{}, err
	}
	disk.Path = path
	if err = os.MkdirAll(s.nativeVolumeDirectory, 0700); err != nil {
		return native.Disk{}, err
	}
	if err = s.nativeDisks.DeleteDisk(ctx, disk); err != nil {
		return native.Disk{}, err
	}
	if err = s.nativeDisks.CreateDisk(ctx, disk, int64(v.Configuration.Size)<<30); err != nil {
		return native.Disk{}, err
	}
	var aead cipher.AEAD
	if v.Encrypted {
		aead, err = blockCipher(key)
		if err != nil {
			return native.Disk{}, err
		}
	}
	var blocks []VolumeBlockInfo
	err = s.repository.View(ctx, func(r Reader) error { var e error; blocks, e = r.VolumeBlocks(v.Key); return e })
	if err != nil {
		return native.Disk{}, err
	}
	if len(blocks) > 0 {
		err = s.nativeDisks.WriteDisk(ctx, disk, func(writer io.WriterAt) error {
			for _, info := range blocks {
				var block VolumeBlockRecord
				err := s.repository.View(ctx, func(r Reader) error { var e error; block, e = r.VolumeBlock(info.Key); return e })
				if err != nil {
					return err
				}
				data, err := openBlockData(aead, block.EncryptionOrigin, info.Key.Index, block.Data)
				if err == nil {
					_, err = writer.WriteAt(data, int64(info.Key.Index)*BlockSize)
				}
				clear(data)
				clear(block.Data)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return native.Disk{}, err
		}
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Volume(v.Key)
		if e != nil {
			return e
		}
		if current.Creation != nil || current.StateMessage != "" || current.NativePath != "" || current.Status == api.VolumeStateDeleting || current.Status == api.VolumeStateDeleted {
			return errors.New("volume changed during native hydration")
		}
		current.NativePath = path
		if e = deleteUnpinnedVolumeBlocks(tx, v.Key); e != nil {
			return e
		}
		return tx.PutVolume(current)
	})
	if err != nil {
		return native.Disk{}, err
	}
	return disk, nil
}

func (s *Service) nativeSnapshotPending(r Reader, v VolumeRecord) (bool, error) {
	rows, err := r.Snapshots(v.Key.Scope)
	if err != nil {
		return false, err
	}
	for _, snapshot := range rows {
		if snapshot.Volume != nil && snapshot.Volume.Source == v.Key && snapshot.Volume.NativeBackupPath != "" {
			return true, nil
		}
	}
	return false, nil
}
