package lambda

import (
	"context"
	"reflect"
	"testing"
	"time"

	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
)

// These source-boundary responses contain no customer records. The regression
// observes committed Lambda checkpoints and the iterator modes used after a
// service reopen/reshard, not an invocation echo from a fabricated data source.
type snapshotPollingSource struct {
	streamConsumer
	description streamDescription
	boundaries  map[string]string
	latest      []string
	positions   map[string]kinesisapi.ShardIteratorType
	beforeRead  func()
}

func (s *snapshotPollingSource) Describe(context.Context) (streamDescription, error) {
	return s.description, nil
}

func (s *snapshotPollingSource) LatestSequence(_ context.Context, shard string) (string, *awswire.Error) {
	s.latest = append(s.latest, shard)
	return s.boundaries[shard], nil
}

func (s *snapshotPollingSource) Read(_ context.Context, _ EventSourceMappingRecord, shard *StreamShardRecord, _ string, _ time.Time) (streamPage, error) {
	if s.beforeRead != nil {
		s.beforeRead()
	}
	s.positions[shard.Key.ShardID] = *kinesisStartingPosition(shard).Type
	return streamPage{Complete: true}, nil
}

func TestStreamLatestSnapshotsAllShardsBeforeReadingAndSurvivesReopen(t *testing.T) {
	s, manual, _, ctx, function, mapping := pollingFixture(t, nil)
	mapping.Settings.Stream.StartingPosition = "LATEST"
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutEventSourceMapping(mapping) }); err != nil {
		t.Fatal(err)
	}
	source := &snapshotPollingSource{
		description: streamDescription{Retention: 24 * time.Hour, Shards: []streamShard{{ID: "left"}, {ID: "right"}}},
		boundaries:  map[string]string{"left": "100000000000000000001", "right": "100000000000000000002", "child": "100000000000000000003"},
		positions:   map[string]kinesisapi.ShardIteratorType{},
	}
	source.beforeRead = func() {
		if err := s.repository.View(ctx, func(r Reader) error {
			shards, err := r.StreamShards(mapping.Key)
			if err != nil {
				return err
			}
			if len(shards) != 2 {
				t.Fatalf("LATEST positions were not atomically committed before source reads: %+v", shards)
			}
			for _, shard := range shards {
				if shard.Checkpoint != source.boundaries[shard.Key.ShardID] {
					t.Fatalf("LATEST skipped the source-owned boundary: %+v", shard)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.pollStreamMapping(ctx, mapping, function, source, map[string]string{}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(source.latest, []string{"left", "right"}) || source.positions["left"] != kinesisapi.ShardIteratorTypeAFTER_SEQUENCE_NUMBER || source.positions["right"] != kinesisapi.ShardIteratorTypeAFTER_SEQUENCE_NUMBER {
		t.Fatalf("LATEST did not use source checkpoints: latest=%v positions=%v", source.latest, source.positions)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopening clears all transient iterators, but must not resample LATEST.
	reopened := aliasOwnerService(t, Config{Repository: s.repository, Clock: manual})
	source.beforeRead = nil
	source.description.Shards = append(source.description.Shards, streamShard{ID: "child", ParentID: "left", AdjacentParentID: "right"})
	if err := reopened.pollStreamMapping(ctx, mapping, function, source, map[string]string{}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(source.latest, []string{"left", "right"}) || source.positions["child"] != kinesisapi.ShardIteratorTypeTRIM_HORIZON {
		t.Fatalf("reopen or reshard discarded new descendant history: latest=%v positions=%v", source.latest, source.positions)
	}
	if err := reopened.repository.View(ctx, func(r Reader) error {
		shards, err := r.StreamShards(mapping.Key)
		if err != nil {
			return err
		}
		if len(shards) != 3 {
			t.Fatalf("reopen lost retained shard state: %+v", shards)
		}
		for _, shard := range shards {
			if shard.Key.ShardID == "child" {
				if shard.Checkpoint != "" || !shard.Complete {
					t.Fatalf("descendant did not start at its retained beginning: %+v", shard)
				}
			} else if shard.Checkpoint != source.boundaries[shard.Key.ShardID] {
				t.Fatalf("reopen resampled an initial LATEST position: %+v", shard)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStreamBatchSizeFlushesBeforeBatchingWindow(t *testing.T) {
	_, manual, _, _, _, mapping := pollingFixture(t, nil)
	mapping.Settings.BatchingWindow = 5 * time.Second
	lane := StreamLane{}
	for range 99 {
		lane.Records = append(lane.Records, pollingStreamRecord(t, "sequence", manual.Now(), false))
	}
	if prepareStreamLane(mapping, &lane, false, manual.Now().Add(5*time.Second-time.Nanosecond)) {
		t.Fatal("underfilled batch ignored the batching window")
	}
	lane.Records = append(lane.Records, pollingStreamRecord(t, "last-sequence", manual.Now(), false))
	if !prepareStreamLane(mapping, &lane, false, manual.Now()) || len(lane.Batches) != 1 || lane.Batches[0].Count != 100 {
		t.Fatalf("BatchSize=100 did not flush a full batch: %+v", lane.Batches)
	}
}
