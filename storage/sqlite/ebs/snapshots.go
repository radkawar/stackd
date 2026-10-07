package ebs

import (
	"database/sql"
	"errors"

	api "stackd/internal/awsapi/ebs"
	domain "stackd/storage/ebs"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ebs/internal/sqlcgen"
)

func (r reader) snapshot(v sqlcgen.EbsSnapshot) (domain.SnapshotRecord, error) {
	out := domain.SnapshotRecord{
		Key:      domain.SnapshotKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID},
		ParentID: v.ParentID, LineageID: v.LineageID,
		VolumeSize: v.VolumeSize, Description: v.Description,
		InitialInput: api.StartSnapshotRequest{
			ClientToken:      stringPointer[api.IdempotencyToken](v.InitialClientToken),
			Description:      stringPointer[api.Description](v.InitialDescription),
			Encrypted:        boolPointer[api.Boolean](v.InitialEncrypted),
			KmsKeyArn:        stringPointer[api.KmsKeyArn](v.InitialKmsKeyArn),
			ParentSnapshotId: stringPointer[api.SnapshotId](v.InitialParentSnapshotID),
			Timeout:          integerPointer[api.Timeout](v.InitialTimeout),
			VolumeSize:       integerPointer[api.VolumeSize](v.InitialVolumeSize),
		},
		Created: v.Created, Status: api.Status(v.Status),
		Sealed: v.Sealed, Readable: v.Readable, Deleted: v.Deleted,
		CompleteAt: timeValue(v.CompleteAt), ReadableAt: timeValue(v.ReadableAt), TimeoutAt: timeValue(v.TimeoutAt),
		DeleteAt:     timeValue(v.DeleteAt),
		StateMessage: v.StateMessage, KMSKeyARN: v.KmsKeyArn, WrappedKey: v.WrappedKey, TokenKey: v.TokenKey,
		Public: v.IsPublic, SharingAt: timeValue(v.SharingAt),
	}
	if v.CopySourceID != "" {
		out.Copy = &domain.SnapshotCopy{
			Source: domain.SnapshotKey{Scope: domain.Scope{
				Partition: v.CopySourcePartition, AccountID: v.CopySourceAccountID, Region: v.CopySourceRegion,
			}, ID: v.CopySourceID},
			Incremental:               v.CopyIncremental,
			CompletionDurationMinutes: int32(v.CopyCompletionDurationMinutes),
			RequestID:                 v.CopyRequestID, ParentEventID: v.CopyParentEventID,
			WorkAt: timeValue(v.CopyWorkAt),
			KeySource: domain.SnapshotKey{Scope: domain.Scope{
				Partition: v.CopyKeySourcePartition, AccountID: v.CopyKeySourceAccountID, Region: v.CopyKeySourceRegion,
			}, ID: v.CopyKeySourceID},
			SourceGrantToken: v.CopySourceGrantToken, DestinationGrantToken: v.CopyDestinationGrantToken,
			DestinationEncryptGrantToken: v.CopyDestinationEncryptGrantToken,
		}
	}
	if v.VolumeSourceID != "" {
		out.Volume = &domain.SnapshotVolume{
			Source: domain.VolumeKey{Scope: domain.Scope{
				Partition: v.VolumeSourcePartition, AccountID: v.VolumeSourceAccountID, Region: v.VolumeSourceRegion,
			}, ID: v.VolumeSourceID},
			RequestID: v.VolumeRequestID, ParentEventID: v.VolumeParentEventID,
			NativeBackupPath: v.NativeBackupPath, NativeBackupReady: v.NativeBackupReady,
			NativeWorkAt: timeValue(v.NativeWorkAt),
			BlocksWorkAt: timeValue(v.BlocksWorkAt),
		}
	}
	if v.InitialTagsPresent {
		rows, err := r.q.ListInitialTags(r.ctx, sqlcgen.ListInitialTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, SnapshotID: v.ID})
		if err != nil {
			return domain.SnapshotRecord{}, err
		}
		out.InitialInput.Tags = make(api.Tags, 0, len(rows))
		for _, row := range rows {
			out.InitialInput.Tags = append(out.InitialInput.Tags, api.Tag{Key: stringPointer[api.TagKey](row.Key), Value: stringPointer[api.TagValue](row.Value)})
		}
	}
	if v.TagsPresent {
		rows, err := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, SnapshotID: v.ID})
		if err != nil {
			return domain.SnapshotRecord{}, err
		}
		out.Tags = make(map[string]string, len(rows))
		for _, row := range rows {
			out.Tags[row.Key] = row.Value
		}
	}
	shares, err := r.q.ListShares(r.ctx, sqlcgen.ListSharesParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, SnapshotID: v.ID})
	if err != nil {
		return domain.SnapshotRecord{}, err
	}
	out.Shares = make([]domain.SnapshotShare, len(shares))
	for i, share := range shares {
		out.Shares[i] = domain.SnapshotShare{AccountID: share.RecipientAccountID, Granted: share.Granted, Readable: share.Readable}
	}
	out.CloudFormationOwner, err = r.cloudFormationClaim(out.Key.Scope, out.Key.ID)
	if err != nil {
		return domain.SnapshotRecord{}, err
	}
	return out, nil
}

func (r reader) Snapshot(k domain.SnapshotKey) (domain.SnapshotRecord, error) {
	v, err := r.q.GetSnapshot(r.ctx, sqlcgen.GetSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID})
	if err != nil {
		return domain.SnapshotRecord{}, missing(err)
	}
	return r.snapshot(v)
}

func (r reader) Snapshots(scope domain.Scope) ([]domain.SnapshotRecord, error) {
	return r.snapshotRows(r.q.ListSnapshots(r.ctx, sqlcgen.ListSnapshotsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}))
}

func (r reader) snapshotRows(rows []sqlcgen.EbsSnapshot, err error) ([]domain.SnapshotRecord, error) {
	if err != nil {
		return nil, err
	}
	out := make([]domain.SnapshotRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.snapshot(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) SnapshotCounts(scope domain.Scope) (domain.SnapshotCounts, error) {
	v, err := r.q.CountSnapshots(r.ctx, sqlcgen.CountSnapshotsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return domain.SnapshotCounts{}, err
	}
	return domain.SnapshotCounts{Total: v.Total, Pending: v.Pending, Copying: v.Copying}, nil
}

func (r reader) SnapshotByToken(scope domain.Scope, token string) (domain.SnapshotRecord, error) {
	v, err := r.q.GetSnapshotByToken(r.ctx, sqlcgen.GetSnapshotByTokenParams{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
		InitialClientToken: sql.NullString{String: token, Valid: true},
	})
	if err != nil {
		return domain.SnapshotRecord{}, missing(err)
	}
	return r.snapshot(v)
}

func (r reader) NextWork() (domain.SnapshotRecord, error) {
	v, err := r.q.NextWork(r.ctx)
	if err != nil {
		return domain.SnapshotRecord{}, missing(err)
	}
	return r.snapshot(v)
}

func (w writer) PutSnapshot(v domain.SnapshotRecord) error {
	k, input := v.Key, v.InitialInput
	params := sqlcgen.PutSnapshotParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID,
		ParentID: v.ParentID, LineageID: v.LineageID,
		VolumeSize: v.VolumeSize, Description: v.Description,
		InitialClientToken: nullableString(input.ClientToken), InitialDescription: nullableString(input.Description),
		InitialEncrypted: nullableBool(input.Encrypted), InitialKmsKeyArn: nullableString(input.KmsKeyArn),
		InitialParentSnapshotID: nullableString(input.ParentSnapshotId),
		InitialTimeout:          nullableInteger(input.Timeout), InitialVolumeSize: nullableInteger(input.VolumeSize),
		InitialTagsPresent: input.Tags != nil,
		Created:            v.Created.UTC(), Status: string(v.Status), Sealed: v.Sealed, Readable: v.Readable, Deleted: v.Deleted,
		CompleteAt: nullableTime(v.CompleteAt), ReadableAt: nullableTime(v.ReadableAt), TimeoutAt: nullableTime(v.TimeoutAt),
		DeleteAt:     nullableTime(v.DeleteAt),
		StateMessage: v.StateMessage, TagsPresent: v.Tags != nil,
		KmsKeyArn: v.KMSKeyARN, WrappedKey: v.WrappedKey, TokenKey: v.TokenKey,
		IsPublic: v.Public, SharingAt: nullableTime(v.SharingAt),
	}
	if v.Copy != nil {
		params.CopySourcePartition = v.Copy.Source.Partition
		params.CopySourceAccountID = v.Copy.Source.AccountID
		params.CopySourceRegion = v.Copy.Source.Region
		params.CopySourceID = v.Copy.Source.ID
		params.CopyIncremental = v.Copy.Incremental
		params.CopyCompletionDurationMinutes = int64(v.Copy.CompletionDurationMinutes)
		params.CopyRequestID = v.Copy.RequestID
		params.CopyParentEventID = v.Copy.ParentEventID
		params.CopyWorkAt = nullableTime(v.Copy.WorkAt)
		params.CopyKeySourcePartition = v.Copy.KeySource.Partition
		params.CopyKeySourceAccountID = v.Copy.KeySource.AccountID
		params.CopyKeySourceRegion = v.Copy.KeySource.Region
		params.CopyKeySourceID = v.Copy.KeySource.ID
		params.CopySourceGrantToken = v.Copy.SourceGrantToken
		params.CopyDestinationGrantToken = v.Copy.DestinationGrantToken
		params.CopyDestinationEncryptGrantToken = v.Copy.DestinationEncryptGrantToken
	}
	if v.Volume != nil {
		params.VolumeSourcePartition = v.Volume.Source.Partition
		params.VolumeSourceAccountID = v.Volume.Source.AccountID
		params.VolumeSourceRegion = v.Volume.Source.Region
		params.VolumeSourceID = v.Volume.Source.ID
		params.VolumeRequestID = v.Volume.RequestID
		params.VolumeParentEventID = v.Volume.ParentEventID
		params.NativeBackupPath = v.Volume.NativeBackupPath
		params.NativeBackupReady = v.Volume.NativeBackupReady
		params.NativeWorkAt = nullableTime(v.Volume.NativeWorkAt)
		params.BlocksWorkAt = nullableTime(v.Volume.BlocksWorkAt)
	}
	if err := w.q.PutSnapshot(w.ctx, params); err != nil {
		return err
	}
	if err := w.putCloudFormationClaim(v.Key.Scope, v.Key.ID, v.CloudFormationOwner); err != nil {
		return err
	}
	if err := w.q.DeleteInitialTags(w.ctx, sqlcgen.DeleteInitialTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SnapshotID: k.ID}); err != nil {
		return err
	}
	for i, tag := range input.Tags {
		if err := w.q.PutInitialTag(w.ctx, sqlcgen.PutInitialTagParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SnapshotID: k.ID,
			Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value),
		}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SnapshotID: k.ID}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SnapshotID: k.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteShares(w.ctx, sqlcgen.DeleteSharesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SnapshotID: k.ID}); err != nil {
		return err
	}
	for _, share := range v.Shares {
		if err := w.q.PutShare(w.ctx, sqlcgen.PutShareParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, SnapshotID: k.ID,
			RecipientAccountID: share.AccountID, Granted: share.Granted, Readable: share.Readable,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteSnapshot(k domain.SnapshotKey) error {
	n, err := w.q.DeleteSnapshot(w.ctx, sqlcgen.DeleteSnapshotParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID})
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (w writer) NextID(scope domain.Scope) (string, error) {
	next, err := w.nextSequence(scope)
	if err != nil {
		return "", err
	}
	return domain.SnapshotID(scope, next), nil
}

func (w writer) nextSequence(scope domain.Scope) (uint64, error) {
	n, err := w.q.GetSequence(w.ctx, sqlcgen.GetSequenceParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	next := uint64(n) + 1
	if next == 0 {
		return 0, errors.New("ebs: resource sequence exhausted")
	}
	if err := w.q.PutSequence(w.ctx, sqlcgen.PutSequenceParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Sequence: sqlite.Uint64(next)}); err != nil {
		return 0, err
	}
	return next, nil
}
