package lambda

import (
	"time"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) StreamShards(k domain.EventSourceMappingKey) ([]domain.StreamShardRecord, error) {
	rows, err := r.q.ListStreamShards(r.ctx, k.ARN())
	if err != nil {
		return nil, err
	}
	out := make([]domain.StreamShardRecord, 0, len(rows))
	for _, row := range rows {
		v := domain.StreamShardRecord{Key: domain.StreamShardKey{Mapping: k, ShardID: row.ShardID}, ParentID: row.ParentID, AdjacentParentID: row.AdjacentParentID, StartingPositionTimestamp: row.StartingPositionTimestamp, Retention: time.Duration(row.RetentionNanoseconds), Checkpoint: row.Checkpoint, ReadComplete: row.ReadComplete, Complete: row.Complete}
		lanes, err := r.q.ListStreamLanes(r.ctx, sqlcgen.ListStreamLanesParams{MappingArn: k.ARN(), ShardID: row.ShardID})
		if err != nil {
			return nil, err
		}
		for _, lane := range lanes {
			l := domain.StreamLane{WindowStart: lane.WindowStart, WindowEnd: lane.WindowEnd, WindowState: lane.WindowState, WindowFinal: lane.WindowFinal, WindowEarly: lane.WindowEarly}
			records, err := r.q.ListStreamRecords(r.ctx, sqlcgen.ListStreamRecordsParams{MappingArn: k.ARN(), ShardID: row.ShardID, Lane: lane.Lane})
			if err != nil {
				return nil, err
			}
			for _, record := range records {
				l.Records = append(l.Records, domain.StreamQueuedRecord{ID: record.RecordID, Sequence: record.SequenceNumber, ItemKey: record.ItemKey, CreatedAt: record.CreatedAt, CapturedAt: record.CapturedAt, Payload: record.Payload})
			}
			batches, err := r.q.ListStreamBatches(r.ctx, sqlcgen.ListStreamBatchesParams{MappingArn: k.ARN(), ShardID: row.ShardID, Lane: lane.Lane})
			if err != nil {
				return nil, err
			}
			for _, batch := range batches {
				l.Batches = append(l.Batches, domain.StreamBatch{Count: int(batch.RecordCount), Attempts: int(batch.Attempts), Due: batch.Due, LastEventID: batch.LastEventID, LastRequestID: batch.LastRequestID, ExecutedVersion: batch.ExecutedVersion, FunctionError: batch.FunctionError, InvokeCount: int(batch.InvokeCount)})
			}
			v.Lanes = append(v.Lanes, l)
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutStreamShard(v domain.StreamShardRecord) error {
	k, shard := v.Key.Mapping, v.Key.ShardID
	arn := k.ARN()
	count, err := w.q.PutStreamShard(w.ctx, sqlcgen.PutStreamShardParams{
		MappingArn: arn, ShardID: shard, ParentID: v.ParentID, AdjacentParentID: v.AdjacentParentID, StartingPositionTimestamp: v.StartingPositionTimestamp, RetentionNanoseconds: int64(v.Retention), Checkpoint: v.Checkpoint, ReadComplete: v.ReadComplete, Complete: v.Complete,
		Partition: k.Partition, Account: k.Account, Region: k.Region, Uuid: k.UUID,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	if err := w.q.DeleteStreamLanes(w.ctx, sqlcgen.DeleteStreamLanesParams{MappingArn: arn, ShardID: shard}); err != nil {
		return err
	}
	for i, lane := range v.Lanes {
		state := []byte(lane.WindowState)
		if state == nil {
			state = []byte{}
		}
		if err := w.q.PutStreamLane(w.ctx, sqlcgen.PutStreamLaneParams{MappingArn: arn, ShardID: shard, Lane: int64(i), WindowStart: lane.WindowStart, WindowEnd: lane.WindowEnd, WindowState: state, WindowFinal: lane.WindowFinal, WindowEarly: lane.WindowEarly}); err != nil {
			return err
		}
		for j, record := range lane.Records {
			if err := w.q.PutStreamRecord(w.ctx, sqlcgen.PutStreamRecordParams{MappingArn: arn, ShardID: shard, Lane: int64(i), Ordinal: int64(j), RecordID: record.ID, SequenceNumber: record.Sequence, ItemKey: record.ItemKey, CreatedAt: record.CreatedAt, CapturedAt: record.CapturedAt, Payload: record.Payload}); err != nil {
				return err
			}
		}
		for j, batch := range lane.Batches {
			if err := w.q.PutStreamBatch(w.ctx, sqlcgen.PutStreamBatchParams{MappingArn: arn, ShardID: shard, Lane: int64(i), Ordinal: int64(j), RecordCount: int64(batch.Count), Attempts: int64(batch.Attempts), Due: batch.Due, LastEventID: batch.LastEventID, LastRequestID: batch.LastRequestID, ExecutedVersion: batch.ExecutedVersion, FunctionError: batch.FunctionError, InvokeCount: int64(batch.InvokeCount)}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (r reader) StreamFailures() ([]domain.StreamFailure, error) {
	rows, err := r.q.ListStreamFailures(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.StreamFailure, 0, len(rows))
	for _, v := range rows {
		scope := domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}
		out = append(out, domain.StreamFailure{ID: v.ID, Mapping: domain.EventSourceMappingKey{Scope: scope, UUID: v.MappingUuid}, Function: domain.FunctionReference{FunctionKey: domain.FunctionKey{Scope: scope, Name: v.FunctionName}, Qualifier: v.FunctionQualifier}, RoleARN: v.RoleArn, DestinationARN: v.DestinationArn, ShardID: v.ShardID, RecordCount: int(v.RecordCount), CreatedAt: v.CreatedAt, ParentEventID: v.ParentEventID, Payload: v.Payload})
	}
	return out, nil
}
func (w writer) PutStreamFailure(v domain.StreamFailure) error {
	return w.q.PutStreamFailure(w.ctx, sqlcgen.PutStreamFailureParams{ID: v.ID, Partition: v.Mapping.Partition, Account: v.Mapping.Account, Region: v.Mapping.Region, MappingUuid: v.Mapping.UUID, FunctionName: v.Function.Name, FunctionQualifier: v.Function.Qualifier, RoleArn: v.RoleARN, DestinationArn: v.DestinationARN, ShardID: v.ShardID, RecordCount: int64(v.RecordCount), CreatedAt: v.CreatedAt, ParentEventID: v.ParentEventID, Payload: v.Payload})
}
func (w writer) DeleteStreamFailure(id string) error { return w.q.DeleteStreamFailure(w.ctx, id) }
