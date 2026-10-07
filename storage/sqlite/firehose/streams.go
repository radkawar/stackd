package firehose

import (
	"database/sql"
	"errors"

	domain "stackd/storage/firehose"
	"stackd/storage/sqlite/firehose/internal/sqlcgen"
)

func (r reader) Stream(key domain.StreamKey) (domain.StreamRecord, error) {
	v, err := r.q.GetStream(r.ctx, sqlcgen.GetStreamParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
	if err != nil {
		return domain.StreamRecord{}, missing(err)
	}
	return r.stream(v)
}

func (r reader) StreamByID(id string) (domain.StreamRecord, error) {
	v, err := r.q.GetStreamByID(r.ctx, id)
	if err != nil {
		return domain.StreamRecord{}, missing(err)
	}
	return r.stream(v)
}

func (r reader) Streams(q domain.StreamQuery) ([]domain.StreamRecord, error) {
	rows, err := r.q.ListStreams(r.ctx, sqlcgen.ListStreamsParams{Partition: q.Scope.Partition, AccountID: q.Scope.AccountID, Region: q.Scope.Region, AfterName: q.After, StreamType: q.Type, RowLimit: rowLimit(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.StreamRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.stream(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) NextLifecycle() (domain.StreamRecord, error) {
	v, err := r.q.NextLifecycle(r.ctx)
	if err != nil {
		return domain.StreamRecord{}, missing(err)
	}
	return r.stream(v)
}

func (r reader) NextSource() (domain.StreamRecord, error) {
	v, err := r.q.NextSource(r.ctx)
	if err != nil {
		return domain.StreamRecord{}, missing(err)
	}
	return r.stream(v)
}

func (r reader) stream(v sqlcgen.FirehoseStream) (domain.StreamRecord, error) {
	out := domain.StreamRecord{
		Key: domain.StreamKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name},
		ID:  v.ID, Status: v.Status, Version: v.Version, Created: v.Created.UTC(), Updated: timePointer(v.Updated), LifecycleDue: v.LifecycleDue.UTC(), BufferID: v.BufferID,
		CFNOwner: v.CfnOwner,
	}
	destination, err := r.configuration("stream:" + v.ID)
	if err != nil {
		return out, err
	}
	out.Destination = destination
	if v.TagsPresent {
		out.Tags = map[string]string{}
	}
	tags, err := r.q.ListTags(r.ctx, v.ID)
	if err != nil {
		return out, err
	}
	for _, tag := range tags {
		out.Tags[tag.Key] = tag.Value
	}
	source, err := r.q.GetSource(r.ctx, v.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	if err == nil {
		out.Source = &domain.KinesisSourceRecord{ARN: source.Arn, RoleARN: source.RoleArn, Created: source.Created.UTC(), DeliveryStart: source.DeliveryStart.UTC(), Due: source.Due.UTC(), RetentionHours: int32(source.RetentionHours)}
	}
	return out, nil
}

func (w writer) PutStream(v domain.StreamRecord) error {
	if err := w.q.PutStream(w.ctx, sqlcgen.PutStreamParams{
		ID: v.ID, Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name,
		Status: v.Status, Version: v.Version, Created: v.Created.UTC(), Updated: nullableTime(v.Updated), LifecycleDue: v.LifecycleDue.UTC(), BufferID: v.BufferID, TagsPresent: v.Tags != nil,
		CfnOwner: v.CFNOwner,
	}); err != nil {
		return err
	}
	if err := w.putConfiguration("stream:"+v.ID, v.ID, sql.NullString{}, v.Destination); err != nil {
		return err
	}
	if err := w.q.DeleteTags(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{StreamID: v.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if v.Source == nil {
		return w.q.DeleteSource(w.ctx, v.ID)
	}
	return w.q.PutSource(w.ctx, sqlcgen.PutSourceParams{StreamID: v.ID, Arn: v.Source.ARN, RoleArn: v.Source.RoleARN, Created: v.Source.Created.UTC(), DeliveryStart: v.Source.DeliveryStart.UTC(), Due: v.Source.Due.UTC(), RetentionHours: int64(v.Source.RetentionHours)})
}

func (w writer) DeleteStream(key domain.StreamKey) error {
	return w.q.DeleteStream(w.ctx, sqlcgen.DeleteStreamParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
}

func (r reader) Checkpoints(streamID string) ([]domain.CheckpointRecord, error) {
	rows, err := r.q.ListCheckpoints(r.ctx, streamID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.CheckpointRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.CheckpointRecord{Key: domain.CheckpointKey{StreamID: row.StreamID, ShardID: row.ShardID}, Sequence: row.Sequence, Closed: row.Closed})
	}
	return out, nil
}

func (w writer) PutCheckpoint(v domain.CheckpointRecord) error {
	return w.q.PutCheckpoint(w.ctx, sqlcgen.PutCheckpointParams{StreamID: v.Key.StreamID, ShardID: v.Key.ShardID, Sequence: v.Sequence, Closed: v.Closed})
}
