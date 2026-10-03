package ebs

import (
	domain "stackd/storage/ebs"
	"stackd/storage/sqlite/ebs/internal/sqlcgen"
)

func (r reader) Block(k domain.BlockKey) (domain.BlockRecord, error) {
	s := k.Snapshot
	v, err := r.q.GetBlock(r.ctx, sqlcgen.GetBlockParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, SnapshotID: s.ID, BlockIndex: int64(k.Index)})
	if err != nil {
		return domain.BlockRecord{}, missing(err)
	}
	return domain.BlockRecord{BlockInfo: domain.BlockInfo{
		Key: k, Checksum: [32]byte(v.Checksum), WrittenSnapshotID: v.WrittenSnapshotID,
		EncryptionOrigin: domain.BlockEncryptionOrigin{Scope: domain.Scope{
			Partition: v.EncryptionOriginPartition, AccountID: v.EncryptionOriginAccountID, Region: v.EncryptionOriginRegion,
		}, ID: v.EncryptionOriginID},
	}, Data: v.Data}, nil
}

func (r reader) Blocks(k domain.SnapshotKey) ([]domain.BlockInfo, error) {
	rows, err := r.q.ListBlocks(r.ctx, sqlcgen.ListBlocksParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SnapshotID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.BlockInfo, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.BlockInfo{
			Key: domain.BlockKey{Snapshot: k, Index: int32(row.BlockIndex)}, Checksum: [32]byte(row.Checksum), WrittenSnapshotID: row.WrittenSnapshotID,
			EncryptionOrigin: domain.BlockEncryptionOrigin{Scope: domain.Scope{
				Partition: row.EncryptionOriginPartition, AccountID: row.EncryptionOriginAccountID, Region: row.EncryptionOriginRegion,
			}, ID: row.EncryptionOriginID},
		})
	}
	return out, nil
}

func (w writer) PutBlock(v domain.BlockRecord) error {
	k, s := v.Key, v.Key.Snapshot
	if err := w.q.PutBlock(w.ctx, sqlcgen.PutBlockParams{
		Partition: s.Partition, AccountID: s.AccountID, Region: s.Region,
		SnapshotID: s.ID, BlockIndex: int64(k.Index), Checksum: v.Checksum[:], WrittenSnapshotID: v.WrittenSnapshotID,
		EncryptionOriginPartition: v.EncryptionOrigin.Partition, EncryptionOriginAccountID: v.EncryptionOrigin.AccountID,
		EncryptionOriginRegion: v.EncryptionOrigin.Region, EncryptionOriginID: v.EncryptionOrigin.ID,
	}); err != nil {
		return err
	}
	return w.q.PutBlockPayload(w.ctx, sqlcgen.PutBlockPayloadParams{
		Partition: s.Partition, AccountID: s.AccountID, Region: s.Region,
		SnapshotID: s.ID, BlockIndex: int64(k.Index), Data: v.Data,
	})
}

func (w writer) DeleteBlocks(k domain.SnapshotKey) error {
	return w.q.DeleteBlocks(w.ctx, sqlcgen.DeleteBlocksParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SnapshotID: k.ID})
}
