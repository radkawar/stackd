package ebs

import (
	domain "stackd/storage/ebs"
	"stackd/storage/sqlite/ebs/internal/sqlcgen"
)

func (r reader) VolumeBlock(k domain.VolumeBlockKey) (domain.VolumeBlockRecord, error) {
	v := k.Volume
	row, err := r.q.GetVolumeBlock(r.ctx, sqlcgen.GetVolumeBlockParams{
		Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, VolumeID: v.ID, BlockIndex: int64(k.Index),
	})
	if err != nil {
		return domain.VolumeBlockRecord{}, missing(err)
	}
	return domain.VolumeBlockRecord{VolumeBlockInfo: domain.VolumeBlockInfo{
		Key: k, Checksum: [32]byte(row.Checksum), WrittenSnapshotID: row.WrittenSnapshotID,
		EncryptionOrigin: domain.BlockEncryptionOrigin{Scope: domain.Scope{
			Partition: row.EncryptionOriginPartition, AccountID: row.EncryptionOriginAccountID, Region: row.EncryptionOriginRegion,
		}, ID: row.EncryptionOriginID},
	}, Data: row.Data}, nil
}

func (r reader) VolumeBlocks(k domain.VolumeKey) ([]domain.VolumeBlockInfo, error) {
	rows, err := r.q.ListVolumeBlocks(r.ctx, sqlcgen.ListVolumeBlocksParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, VolumeID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.VolumeBlockInfo, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.VolumeBlockInfo{
			Key:      domain.VolumeBlockKey{Volume: k, Index: int32(row.BlockIndex)},
			Checksum: [32]byte(row.Checksum), WrittenSnapshotID: row.WrittenSnapshotID,
			EncryptionOrigin: domain.BlockEncryptionOrigin{Scope: domain.Scope{
				Partition: row.EncryptionOriginPartition, AccountID: row.EncryptionOriginAccountID, Region: row.EncryptionOriginRegion,
			}, ID: row.EncryptionOriginID},
		})
	}
	return out, nil
}

func (w writer) PutVolumeBlock(v domain.VolumeBlockRecord) error {
	k, volume := v.Key, v.Key.Volume
	if err := w.q.PutVolumeBlock(w.ctx, sqlcgen.PutVolumeBlockParams{
		Partition: volume.Partition, AccountID: volume.AccountID, Region: volume.Region,
		VolumeID: volume.ID, BlockIndex: int64(k.Index), Checksum: v.Checksum[:], WrittenSnapshotID: v.WrittenSnapshotID,
		EncryptionOriginPartition: v.EncryptionOrigin.Partition, EncryptionOriginAccountID: v.EncryptionOrigin.AccountID,
		EncryptionOriginRegion: v.EncryptionOrigin.Region, EncryptionOriginID: v.EncryptionOrigin.ID,
	}); err != nil {
		return err
	}
	return w.q.PutVolumeBlockPayload(w.ctx, sqlcgen.PutVolumeBlockPayloadParams{
		Partition: volume.Partition, AccountID: volume.AccountID, Region: volume.Region,
		VolumeID: volume.ID, BlockIndex: int64(k.Index), Data: v.Data,
	})
}

func (w writer) DeleteVolumeBlocks(k domain.VolumeKey) error {
	return w.q.DeleteVolumeBlocks(w.ctx, sqlcgen.DeleteVolumeBlocksParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, VolumeID: k.ID})
}
