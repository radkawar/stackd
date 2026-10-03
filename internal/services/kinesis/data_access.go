package kinesis

import (
	"context"

	engine "stackd/engine/kinesis"
)

// openStream authorizes before waiting, then repeats authorization under the
// native stream gate against current identity, policies, tags and topology.
// Incarnation fencing prevents a replacement from redirecting the operation.
// The returned release function owns the gate; no repository callback is held.
func (s *Service) openStream(ctx context.Context, name, resourceARN, action string) (StreamRecord, []ShardRecord, engine.Log, func(), error) {
	var stream StreamRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		stream, err = s.stream(r.Context(), r, name, resourceARN, action)
		return err
	})
	if err != nil {
		return StreamRecord{}, nil, nil, nil, err
	}
	return s.openStreamRecord(ctx, stream, stream.Key.ARN(), action)
}

func (s *Service) openStreamRecord(ctx context.Context, stream StreamRecord, resourceARN, action string) (StreamRecord, []ShardRecord, engine.Log, func(), error) {
	id := stream.EngineID
	release, err := s.engines.lock(ctx, id)
	if err != nil {
		return StreamRecord{}, nil, nil, nil, err
	}
	var shards []ShardRecord
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		stream, err = s.consumingStream(r.Context(), r, resourceARN, action)
		if err != nil {
			return err
		}
		if stream.EngineID != id {
			return ErrNotFound
		}
		if err := requireReadable(stream); err != nil {
			return err
		}
		shards, err = r.Shards(stream.Key)
		return err
	})
	if err != nil {
		release()
		return StreamRecord{}, nil, nil, nil, err
	}
	log, err := s.engines.log(ctx, stream.Specification())
	if err != nil {
		release()
		return StreamRecord{}, nil, nil, nil, err
	}
	rememberStream(ctx, stream)
	return stream, shards, log, release, nil
}

func findShard(shards []ShardRecord, id string) (ShardRecord, error) {
	for _, shard := range shards {
		if shard.Key.ID() == id && shard.State != ShardOpening {
			return shard, nil
		}
	}
	return ShardRecord{}, failure("ResourceNotFoundException", "Requested shard was not found: "+id)
}
