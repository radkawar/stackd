package firehose

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/kinesis"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/kinesisaggregation"
	"stackd/internal/scheduler"
)

// Polling and retry pacing are local service-time policies. Native captures
// establish retained recovery, not universal polling/permission propagation times.
const sourcePollInterval = time.Second
const sourceRetryInterval = 30 * time.Second

type sourceJobs struct{ s *Service }

func (j sourceJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	if j.s.source == nil {
		return
	}
	err = j.s.repository.View(ctx, func(r Reader) error {
		v, err := r.NextSource()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		job, found = streamJob(v, v.Source.Due), true
		return nil
	})
	return
}
func (j sourceJobs) Run(ctx context.Context, job scheduler.Job) error {
	var stream StreamRecord
	eligible := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		v, err := r.StreamByID(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Status != "ACTIVE" || v.Source == nil || uint64(v.Version) != job.Version || !v.Source.Due.Equal(job.Due) || v.Source.Due.After(j.s.clock.Now()) {
			return nil
		}
		stream, eligible = v, true
		return nil
	})
	if err != nil || !eligible {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: stream.Key.Partition, AccountID: stream.Key.AccountID, Region: stream.Key.Region})
	description, rejected := j.s.source.Describe(ctx, stream.Key, *stream.Source)
	if rejected != nil {
		return j.s.finishSourcePoll(ctx, stream, rejected)
	}
	// TODO: Comeback — calibrate same-ARN source recreation recovery beyond the
	// captured five-minute non-recovery window. Never silently attach old
	// checkpoints to the replacement stream incarnation.
	if description.StreamCreationTimestamp == nil || !time.Time(*description.StreamCreationTimestamp).Equal(stream.Source.Created) {
		return j.s.finishSourcePoll(ctx, stream, failure("ResourceNotFoundException", "The configured Kinesis source incarnation no longer exists."))
	}
	if description.RetentionPeriodHours != nil {
		stream.Source.RetentionHours = int32(*description.RetentionPeriodHours)
	}
	var checkpoints []CheckpointRecord
	if err := j.s.repository.View(ctx, func(r Reader) error { var err error; checkpoints, err = r.Checkpoints(stream.ID); return err }); err != nil {
		return err
	}
	positions := make(map[string]CheckpointRecord, len(checkpoints))
	for _, checkpoint := range checkpoints {
		positions[checkpoint.Key.ShardID] = checkpoint
	}
	shards := make(map[string]bool, len(description.Shards))
	for _, shard := range description.Shards {
		shards[value(shard.ShardId)] = true
	}
	for _, shard := range description.Shards {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := value(shard.ShardId)
		checkpoint := positions[id]
		if checkpoint.Closed {
			continue
		}
		parent, adjacent := value(shard.ParentShardId), value(shard.AdjacentParentShardId)
		if shards[parent] && !positions[parent].Closed || shards[adjacent] && !positions[adjacent].Closed {
			continue
		}
		closed, wire, err := j.s.pollShard(ctx, stream, id, checkpoint)
		if err != nil {
			return err
		}
		if wire != nil {
			rejected = wire
			continue
		}
		if closed {
			checkpoint.Closed = true
			positions[id] = checkpoint
		}
	}
	return j.s.finishSourcePoll(ctx, stream, rejected)
}

func (s *Service) pollShard(ctx context.Context, stream StreamRecord, shardID string, checkpoint CheckpointRecord) (bool, *awswire.Error, error) {
	input := &api.GetShardIteratorInput{StreamARN: new(api.StreamARN(stream.Source.ARN)), ShardId: new(api.ShardId(shardID))}
	if checkpoint.Sequence != "" {
		input.ShardIteratorType = new(api.ShardIteratorTypeAFTER_SEQUENCE_NUMBER)
		input.StartingSequenceNumber = new(api.SequenceNumber(checkpoint.Sequence))
	} else {
		input.ShardIteratorType = new(api.ShardIteratorTypeAT_TIMESTAMP)
		input.Timestamp = new(api.Timestamp(stream.Source.DeliveryStart))
	}
	iterator, rejected := s.source.Iterator(ctx, stream.Key, *stream.Source, input)
	if rejected != nil {
		return false, rejected, nil
	}
	page, rejected := s.source.Records(ctx, stream.Key, *stream.Source, &api.GetRecordsInput{StreamARN: input.StreamARN, ShardIterator: iterator.ShardIterator})
	if rejected != nil {
		return false, rejected, nil
	}
	closed := value(page.NextShardIterator) == ""
	if len(page.Records) == 0 && !closed {
		return false, nil, nil
	}
	rows := make([]RecordRecord, 0, len(page.Records))
	for _, record := range page.Records {
		arrived := s.clock.Now().UTC()
		if record.ApproximateArrivalTimestamp != nil {
			arrived = time.Time(*record.ApproximateArrivalTimestamp).UTC()
		}
		sequence := value(record.SequenceNumber)
		children, aggregated := kinesisaggregation.Decode(record.Data)
		if !aggregated {
			rows = append(rows, RecordRecord{Data: record.Data, Arrived: arrived, Kinesis: &KinesisRecordMetadata{ShardID: shardID, PartitionKey: value(record.PartitionKey), SequenceNumber: sequence}})
			continue
		}
		// Retain deaggregated originals, not the transport envelope. Every child
		// is committed with the outer sequence checkpoint in the transaction below.
		for subsequence, child := range children {
			rows = append(rows, RecordRecord{Data: child.Data, Arrived: arrived, Kinesis: &KinesisRecordMetadata{ShardID: shardID, PartitionKey: child.PartitionKey, SequenceNumber: sequence, SubsequenceNumber: int64(subsequence)}})
		}
	}
	checkpoint.Key = CheckpointKey{StreamID: stream.ID, ShardID: shardID}
	checkpoint.Closed = closed
	if len(page.Records) > 0 {
		checkpoint.Sequence = value(page.Records[len(page.Records)-1].SequenceNumber)
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.StreamByID(stream.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Status != "ACTIVE" {
			return nil
		}
		if err := s.appendRecords(tx.Context(), tx, &current, rows); err != nil {
			return err
		}
		return tx.PutCheckpoint(checkpoint)
	})
	return closed, nil, err
}

func (s *Service) finishSourcePoll(ctx context.Context, stream StreamRecord, rejected *awswire.Error) error {
	interval := sourcePollInterval
	if rejected != nil {
		interval = sourceRetryInterval
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.StreamByID(stream.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Status != "ACTIVE" {
			return nil
		}
		current.Source.Due = s.clock.Now().UTC().Add(interval)
		current.Source.RetentionHours = stream.Source.RetentionHours
		return tx.PutStream(current)
	})
	if err != nil {
		return err
	}
	if rejected == nil || s.diagnostics == nil {
		return nil
	}
	code, message := "", ""
	switch rejected.Code {
	case "AccessDenied", "AccessDeniedException":
		code = "Kinesis.AccessDenied"
		message = "Access was denied when calling Kinesis. Ensure the access policy on the IAM role used allows access to the appropriate Kinesis APIs."
	case "ResourceNotFoundException":
		code = "Kinesis.ResourceNotFound"
		message = "Firehose failed to read from the stream. If the Firehose is attached with Kinesis Stream, the stream may not exist, or the shard may have been merged or split. If the Firehose is of DirectPut type, the Firehose may not exist any more."
	}
	if code == "" {
		return nil
	}
	return s.diagnostics.Report(ctx, stream, code, message)
}
