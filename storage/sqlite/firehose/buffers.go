package firehose

import (
	"database/sql"
	"errors"

	domain "stackd/storage/firehose"
	"stackd/storage/sqlite/firehose/internal/sqlcgen"
)

func (r reader) Buffer(id string) (domain.BufferRecord, error) {
	v, err := r.q.GetBuffer(r.ctx, id)
	if err != nil {
		return domain.BufferRecord{}, missing(err)
	}
	return r.buffer(v)
}

func (r reader) OpenOutputBuffer(streamID string, version int64, kind domain.BufferKind) (domain.BufferRecord, error) {
	v, err := r.q.OpenOutputBuffer(r.ctx, sqlcgen.OpenOutputBufferParams{StreamID: streamID, StreamVersion: version, Kind: string(kind)})
	if err != nil {
		return domain.BufferRecord{}, missing(err)
	}
	return r.buffer(v)
}

func (r reader) NextDelivery() (domain.BufferRecord, error) {
	v, err := r.q.NextDelivery(r.ctx)
	if err != nil {
		return domain.BufferRecord{}, missing(err)
	}
	return r.buffer(v)
}

func (r reader) buffer(v sqlcgen.FirehoseBuffer) (domain.BufferRecord, error) {
	out := domain.BufferRecord{
		ID: v.ID, StreamID: v.StreamID, Kind: domain.BufferKind(v.Kind),
		Stream:  domain.StreamKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name},
		Created: v.Created.UTC(), Due: v.Due.UTC(), Count: v.Count, Bytes: v.Bytes,
		ParentEventID: v.ParentEventID, ObjectKey: v.ObjectKey, StreamVersion: v.StreamVersion,
	}
	configuration, err := r.configuration("buffer:" + v.ID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return out, err
	}
	if err == nil {
		out.Configuration = &configuration
	}
	return out, nil
}

func (w writer) PutBuffer(v domain.BufferRecord) error {
	if err := w.q.PutBuffer(w.ctx, sqlcgen.PutBufferParams{
		ID: v.ID, StreamID: v.StreamID, Kind: string(v.Kind), Partition: v.Stream.Partition, AccountID: v.Stream.AccountID, Region: v.Stream.Region, Name: v.Stream.Name,
		Created: v.Created.UTC(), Due: v.Due.UTC(), Count: v.Count, Bytes: v.Bytes, ParentEventID: v.ParentEventID, ObjectKey: v.ObjectKey, StreamVersion: v.StreamVersion,
	}); err != nil {
		return err
	}
	if v.Configuration == nil {
		return w.q.DeleteConfiguration(w.ctx, "buffer:"+v.ID)
	}
	return w.putConfiguration("buffer:"+v.ID, v.StreamID, sql.NullString{String: v.ID, Valid: true}, *v.Configuration)
}

func (w writer) DeleteBuffer(id string) error { return w.q.DeleteBuffer(w.ctx, id) }

func (r reader) Records(bufferID string) ([]domain.RecordRecord, error) {
	rows, err := r.q.ListRecords(r.ctx, bufferID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.RecordRecord, 0, len(rows))
	for _, row := range rows {
		record := domain.RecordRecord{Key: domain.RecordKey{BufferID: row.BufferID, Position: row.Position}, Data: row.Data, Arrived: row.Arrived.UTC(), OriginalBytes: row.OriginalBytes}
		if row.KinesisShardID.Valid {
			record.Kinesis = &domain.KinesisRecordMetadata{ShardID: row.KinesisShardID.String, PartitionKey: row.KinesisPartitionKey.String, SequenceNumber: row.KinesisSequenceNumber.String, SubsequenceNumber: row.KinesisSubsequenceNumber}
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutRecord(v domain.RecordRecord) error {
	row := sqlcgen.PutRecordParams{BufferID: v.Key.BufferID, Position: v.Key.Position, Data: v.Data, Arrived: v.Arrived.UTC(), OriginalBytes: v.OriginalBytes}
	if v.Kinesis != nil {
		row.KinesisShardID = nullableString(&v.Kinesis.ShardID)
		row.KinesisPartitionKey = nullableString(&v.Kinesis.PartitionKey)
		row.KinesisSequenceNumber = nullableString(&v.Kinesis.SequenceNumber)
		row.KinesisSubsequenceNumber = v.Kinesis.SubsequenceNumber
	}
	return w.q.PutRecord(w.ctx, row)
}

func (r reader) Processing(id string) (domain.ProcessingRecord, error) {
	v, err := r.q.GetProcessing(r.ctx, id)
	if err != nil {
		return domain.ProcessingRecord{}, missing(err)
	}
	return processing(v), nil
}

func (r reader) NextProcessing() (domain.ProcessingRecord, error) {
	v, err := r.q.NextProcessing(r.ctx)
	if err != nil {
		return domain.ProcessingRecord{}, missing(err)
	}
	return processing(v), nil
}

func (r reader) InFlightProcessing() ([]domain.ProcessingRecord, error) {
	rows, err := r.q.InFlightProcessing(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ProcessingRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, processing(row))
	}
	return out, nil
}

func processing(v sqlcgen.FirehoseProcessing) domain.ProcessingRecord {
	return domain.ProcessingRecord{BufferID: v.BufferID, State: domain.ProcessingState(v.State), Attempts: int32(v.Attempts), Due: v.Due.UTC()}
}

func (w writer) PutProcessing(v domain.ProcessingRecord) error {
	return w.q.PutProcessing(w.ctx, sqlcgen.PutProcessingParams{BufferID: v.BufferID, State: string(v.State), Attempts: int64(v.Attempts), Due: v.Due.UTC()})
}
