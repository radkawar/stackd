package dynamodb

import (
	"database/sql"
	"encoding/json"
	"errors"
	api "stackd/internal/awsapi/dynamodbstreams"
	domain "stackd/storage/dynamodb"
	"stackd/storage/sqlite/dynamodb/internal/sqlcgen"
	"time"
)

func decodeStream(row sqlcgen.DynamodbStream) (domain.StreamGeneration, error) {
	scope := domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}
	v := domain.StreamGeneration{Key: domain.PolicyKey{Scope: scope, ResourceARN: row.StreamArn}, Table: domain.TableKey{Scope: scope, Name: row.TableName}, DatabaseID: row.DatabaseID, PhysicalName: row.PhysicalName, NativeARN: row.NativeArn, Label: row.Label, CreatedAt: row.CreatedAt, ClosedAt: row.ClosedAt, ViewType: api.StreamViewType(row.ViewType)}
	err := json.Unmarshal(row.KeySchema, &v.KeySchema)
	return v, err
}
func (r reader) Stream(k domain.PolicyKey) (domain.StreamGeneration, error) {
	row, err := r.q.GetStream(r.ctx, sqlcgen.GetStreamParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, StreamArn: k.ResourceARN})
	if err != nil {
		return domain.StreamGeneration{}, missing(err)
	}
	return decodeStream(row)
}
func (r reader) Streams() ([]domain.StreamGeneration, error) {
	rows, err := r.q.ListStreams(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.StreamGeneration, len(rows))
	for i, row := range rows {
		out[i], err = decodeStream(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (w writer) PutStream(v domain.StreamGeneration) error {
	schema, err := json.Marshal(v.KeySchema)
	if err != nil {
		return err
	}
	return w.q.PutStream(w.ctx, sqlcgen.PutStreamParams{StreamArn: v.Key.ResourceARN, Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, TableName: v.Table.Name, DatabaseID: v.DatabaseID, PhysicalName: v.PhysicalName, NativeArn: v.NativeARN, Label: v.Label, CreatedAt: v.CreatedAt, ClosedAt: v.ClosedAt, ViewType: string(v.ViewType), KeySchema: schema})
}
func (w writer) DeleteStream(k domain.PolicyKey) error {
	return w.q.DeleteStream(w.ctx, sqlcgen.DeleteStreamParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, StreamArn: k.ResourceARN})
}
func (r reader) StreamShards(arn string) ([]domain.StreamShard, error) {
	rows, err := r.q.ListStreamShards(r.ctx, arn)
	if err != nil {
		return nil, err
	}
	out := make([]domain.StreamShard, len(rows))
	for i, row := range rows {
		out[i] = domain.StreamShard{StreamARN: row.StreamArn, ID: row.ShardID, ParentID: row.ParentID, Start: row.StartSequence, End: row.EndSequence, Checkpoint: row.Checkpoint, TrimmedThrough: row.TrimmedThrough, Drained: row.Drained}
	}
	return out, nil
}
func (w writer) PutStreamShard(v domain.StreamShard) error {
	return w.q.PutStreamShard(w.ctx, sqlcgen.PutStreamShardParams{StreamArn: v.StreamARN, ShardID: v.ID, ParentID: v.ParentID, StartSequence: v.Start, EndSequence: v.End, Checkpoint: v.Checkpoint, TrimmedThrough: v.TrimmedThrough, Drained: v.Drained})
}
func (r reader) StreamEntries(q domain.StreamEntryQuery) ([]domain.StreamEntry, error) {
	rows, err := r.q.ListStreamEntries(r.ctx, sqlcgen.ListStreamEntriesParams{StreamArn: q.StreamARN, ShardID: q.ShardID, Position: q.Position, Inclusive: q.Inclusive, RecordLimit: int64(min(max(q.Limit, 0), 1000))})
	if err != nil {
		return nil, err
	}
	out := make([]domain.StreamEntry, len(rows))
	for i, row := range rows {
		d := api.Record{EventID: stringPointer[api.String](row.EventID), EventName: stringPointer[api.OperationType](row.EventName), EventSource: stringPointer[api.String](row.EventSource), EventVersion: stringPointer[api.String](row.EventVersion), AwsRegion: stringPointer[api.String](row.AwsRegion), Dynamodb: &api.StreamRecord{ApproximateCreationDateTime: &row.CreatedAt, SequenceNumber: new(api.SequenceNumber(row.Sequence)), SizeBytes: integerPointer[api.PositiveLongObject](row.SizeBytes), StreamViewType: stringPointer[api.StreamViewType](row.ViewType)}}
		if row.IdentityType.Valid || row.IdentityPrincipal.Valid {
			d.UserIdentity = &api.Identity{Type: stringPointer[api.String](row.IdentityType), PrincipalId: stringPointer[api.String](row.IdentityPrincipal)}
		}
		if err := unmarshalFields(jsonReadField{row.KeysData, &d.Dynamodb.Keys}, jsonReadField{row.NewImage, &d.Dynamodb.NewImage}, jsonReadField{row.OldImage, &d.Dynamodb.OldImage}); err != nil {
			return nil, err
		}
		out[i] = domain.StreamEntry{StreamARN: row.StreamArn, ShardID: row.ShardID, Sequence: row.Sequence, CreatedAt: row.CreatedAt, Data: d}
	}
	return out, nil
}
func (w writer) PutStreamEntry(v domain.StreamEntry) error {
	d := v.Data
	p := sqlcgen.PutStreamEntryParams{StreamArn: v.StreamARN, ShardID: v.ShardID, Sequence: v.Sequence, CreatedAt: v.CreatedAt, EventID: nullableString(d.EventID), EventName: nullableString(d.EventName), EventSource: nullableString(d.EventSource), EventVersion: nullableString(d.EventVersion), AwsRegion: nullableString(d.AwsRegion)}
	if d.UserIdentity != nil {
		p.IdentityType = nullableString(d.UserIdentity.Type)
		p.IdentityPrincipal = nullableString(d.UserIdentity.PrincipalId)
	}
	p.SizeBytes = nullableInteger(d.Dynamodb.SizeBytes)
	p.ViewType = nullableString(d.Dynamodb.StreamViewType)
	if err := marshalFields(jsonWriteField{&p.KeysData, d.Dynamodb.Keys}, jsonWriteField{&p.NewImage, d.Dynamodb.NewImage}, jsonWriteField{&p.OldImage, d.Dynamodb.OldImage}); err != nil {
		return err
	}
	return w.q.PutStreamEntry(w.ctx, p)
}
func (w writer) TrimStreamEntries(arn string, cutoff time.Time) (time.Time, error) {
	if err := w.q.AdvanceStreamTrimPoints(w.ctx, sqlcgen.AdvanceStreamTrimPointsParams{StreamArn: arn, Cutoff: cutoff}); err != nil {
		return time.Time{}, err
	}
	if err := w.q.DeleteExpiredStreamEntries(w.ctx, sqlcgen.DeleteExpiredStreamEntriesParams{StreamArn: arn, Cutoff: cutoff}); err != nil {
		return time.Time{}, err
	}
	oldest, err := w.q.OldestStreamEntry(w.ctx, arn)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return oldest, err
}
