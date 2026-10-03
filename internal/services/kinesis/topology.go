package kinesis

import (
	"math/big"
	"slices"

	api "stackd/internal/awsapi/kinesis"
)

func hashBoundary(index, count int32) *big.Int {
	span := new(big.Int).Lsh(big.NewInt(1), 128)
	return span.Quo(span.Mul(span, big.NewInt(int64(index))), big.NewInt(int64(count)))
}

func newShard(stream StreamRecord, partition int32, start, end *big.Int, parents ...ShardRecord) ShardRecord {
	key := ShardKey{Stream: stream.Key, Partition: partition}
	shard := ShardRecord{Key: key, State: ShardOpening, Data: api.Shard{
		ShardId:             new(api.ShardId(key.ID())),
		HashKeyRange:        &api.HashKeyRange{StartingHashKey: new(api.HashKey(start.String())), EndingHashKey: new(api.HashKey(end.String()))},
		SequenceNumberRange: &api.SequenceNumberRange{StartingSequenceNumber: new(sequenceStart(stream.EngineID, partition))},
	}}
	if len(parents) > 0 {
		shard.Data.ParentShardId = new(api.ShardId(parents[0].Key.ID()))
	}
	if len(parents) > 1 {
		shard.Data.AdjacentParentShardId = new(api.ShardId(parents[1].Key.ID()))
	}
	return shard
}

func initialShards(stream StreamRecord, count int32) []ShardRecord {
	shards := make([]ShardRecord, 0, count)
	for i := range count {
		end := hashBoundary(i+1, count)
		end.Sub(end, big.NewInt(1))
		shards = append(shards, newShard(stream, i, hashBoundary(i, count), end))
	}
	return shards
}

// topologyPlan retains a binary ancestry graph. Intermediate shards remain
// addressable so a reader can drain every closed parent before following children.
// Native partitions are allocated once and never reused for another shard.
type topologyPlan struct {
	stream StreamRecord
	shards []ShardRecord
	peak   int32
}

func (p *topologyPlan) add(start, end *big.Int, parents ...ShardRecord) shardRoute {
	shard := newShard(p.stream, p.stream.NextPartition, start, end, parents...)
	p.stream.NextPartition++
	p.shards = append(p.shards, shard)
	return shardRoute{shard: shard, start: start, end: end}
}

func (p *topologyPlan) split(parent shardRoute, boundary *big.Int) (shardRoute, shardRoute) {
	p.peak++
	leftEnd := new(big.Int).Sub(boundary, big.NewInt(1))
	return p.add(parent.start, leftEnd, parent.shard), p.add(boundary, parent.end, parent.shard)
}

func (p *topologyPlan) merge(left, right shardRoute) shardRoute {
	return p.add(left.start, right.end, left.shard, right.shard)
}

func (p *topologyPlan) commit(tx Transaction, update StreamUpdate) error {
	if streamMode(p.stream) == api.StreamModePROVISIONED {
		extra := p.peak - int32(*p.stream.Data.OpenShardCount)
		if err := checkStreamCapacity(tx, p.stream.Key.Scope, api.StreamModePROVISIONED, extra, false); err != nil {
			return err
		}
	}
	for _, shard := range p.shards {
		if err := tx.PutShard(shard); err != nil {
			return err
		}
	}
	update.PeakShardCount = p.peak
	return beginStreamUpdate(tx, p.stream, update)
}

func (s *Service) scheduleReshard(tx Transaction, stream StreamRecord, count int32, update StreamUpdate) error {
	shards, err := tx.Shards(stream.Key)
	if err != nil {
		return err
	}
	routes, err := shardRoutes(shards)
	if err != nil {
		return err
	}
	slices.SortFunc(routes, func(a, b shardRoute) int { return a.start.Cmp(b.start) })
	plan := topologyPlan{stream: stream, peak: int32(len(routes))}
	// Split at every requested boundary before merging within each final range.
	// This models the transient shard quota, not just the final leaf count.
	pieces := make([]shardRoute, 0, len(routes)+int(count))
	next := int32(1)
	for _, route := range routes {
		for next < count && hashBoundary(next, count).Cmp(route.start) <= 0 {
			next++
		}
		for next < count {
			boundary := hashBoundary(next, count)
			if boundary.Cmp(route.end) > 0 {
				break
			}
			var left shardRoute
			left, route = plan.split(route, boundary)
			pieces = append(pieces, left)
			next++
		}
		pieces = append(pieces, route)
	}
	position := 0
	for i := int32(0); i < count; i++ {
		end := hashBoundary(i+1, count)
		end.Sub(end, big.NewInt(1))
		route := pieces[position]
		position++
		for route.end.Cmp(end) < 0 {
			route = plan.merge(route, pieces[position])
			position++
		}
	}
	return plan.commit(tx, update)
}
