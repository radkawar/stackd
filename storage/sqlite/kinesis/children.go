package kinesis

import (
	api "stackd/internal/awsapi/kinesis"
	domain "stackd/storage/kinesis"
	"stackd/storage/sqlite/kinesis/internal/sqlcgen"
)

func (r reader) Shards(k domain.StreamKey) ([]domain.ShardRecord, error) {
	rows, err := r.q.ListShards(r.ctx, sqlcgen.ListShardsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ShardRecord, len(rows))
	for i, v := range rows {
		d := api.Shard{ShardId: stringPointer[api.ShardId](v.ShardID), ParentShardId: stringPointer[api.ShardId](v.ParentID), AdjacentParentShardId: stringPointer[api.ShardId](v.AdjacentParentID)}
		if v.HashPresent {
			d.HashKeyRange = &api.HashKeyRange{StartingHashKey: stringPointer[api.HashKey](v.HashStart), EndingHashKey: stringPointer[api.HashKey](v.HashEnd)}
		}
		if v.SequencePresent {
			d.SequenceNumberRange = &api.SequenceNumberRange{StartingSequenceNumber: stringPointer[api.SequenceNumber](v.SequenceStart), EndingSequenceNumber: stringPointer[api.SequenceNumber](v.SequenceEnd)}
		}
		out[i] = domain.ShardRecord{Key: domain.ShardKey{Stream: k, Partition: int32(v.NativePartition)}, Data: d, State: domain.ShardState(v.State), OpenedAt: v.OpenedAt.UTC(), ClosedAt: v.ClosedAt.UTC()}
	}
	return out, nil
}
func (w writer) PutShard(v domain.ShardRecord) error {
	k, d := v.Key.Stream, &v.Data
	p := sqlcgen.PutShardParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, NativePartition: int64(v.Key.Partition), State: string(v.State), OpenedAt: v.OpenedAt.UTC(), ClosedAt: v.ClosedAt.UTC(), ShardID: nullableString(d.ShardId), ParentID: nullableString(d.ParentShardId), AdjacentParentID: nullableString(d.AdjacentParentShardId), HashPresent: d.HashKeyRange != nil, SequencePresent: d.SequenceNumberRange != nil}
	if d.HashKeyRange != nil {
		p.HashStart = nullableString(d.HashKeyRange.StartingHashKey)
		p.HashEnd = nullableString(d.HashKeyRange.EndingHashKey)
	}
	if d.SequenceNumberRange != nil {
		p.SequenceStart = nullableString(d.SequenceNumberRange.StartingSequenceNumber)
		p.SequenceEnd = nullableString(d.SequenceNumberRange.EndingSequenceNumber)
	}
	return w.q.PutShard(w.ctx, p)
}
func consumer(v sqlcgen.KinesisConsumer) domain.ConsumerRecord {
	k := domain.ConsumerKey{Stream: domain.StreamKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Name: v.ConsumerName, CreatedAt: v.CreatedAt}
	return domain.ConsumerRecord{Key: k, Owner: domain.ResourceOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken}, DeleteAt: v.DeleteAt.UTC(), Data: api.ConsumerDescription{ConsumerARN: stringPointer[api.ConsumerARN](v.ConsumerArn), ConsumerCreationTimestamp: timePointer(v.CreationTimestamp), ConsumerName: stringPointer[api.ConsumerName](v.DataName), ConsumerStatus: stringPointer[api.ConsumerStatus](v.Status), StreamARN: stringPointer[api.StreamARN](v.StreamArn)}}
}
func (r reader) Consumer(key domain.ConsumerKey) (domain.ConsumerRecord, error) {
	k := key.Stream
	row, err := r.q.GetConsumer(r.ctx, sqlcgen.GetConsumerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ConsumerName: key.Name, CreatedAt: key.CreatedAt})
	if err != nil {
		return domain.ConsumerRecord{}, missing(err)
	}
	return consumer(row), nil
}
func (r reader) Consumers(k domain.StreamKey) ([]domain.ConsumerRecord, error) {
	rows, err := r.q.ListConsumers(r.ctx, sqlcgen.ListConsumersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ConsumerRecord, len(rows))
	for i, v := range rows {
		out[i] = consumer(v)
	}
	return out, nil
}
func (w writer) PutConsumer(v domain.ConsumerRecord) error {
	k, d := v.Key.Stream, &v.Data
	if err := w.q.PutConsumer(w.ctx, sqlcgen.PutConsumerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ConsumerName: v.Key.Name, CreatedAt: v.Key.CreatedAt, ConsumerArn: nullableString(d.ConsumerARN), CreationTimestamp: nullableTime(d.ConsumerCreationTimestamp), DataName: nullableString(d.ConsumerName), Status: nullableString(d.ConsumerStatus), StreamArn: nullableString(d.StreamARN), DeleteAt: v.DeleteAt.UTC()}); err != nil {
		return err
	}
	return w.q.SetConsumerOwner(w.ctx, sqlcgen.SetConsumerOwnerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ConsumerName: v.Key.Name, CreatedAt: v.Key.CreatedAt, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token})
}
func (w writer) DeleteConsumer(key domain.ConsumerKey) error {
	k := key.Stream
	if err := w.deleteResource(domain.ResourceKey{Scope: k.Scope, ARN: key.ARN()}); err != nil {
		return err
	}
	return w.q.DeleteConsumer(w.ctx, sqlcgen.DeleteConsumerParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ConsumerName: key.Name, CreatedAt: key.CreatedAt})
}
