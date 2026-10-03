package pipes

import (
	"context"
	"errors"
	"hash/fnv"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type pipeJobs struct {
	s *Service
}

func (j pipeJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		all, err := r.Pipes()
		if err != nil {
			return err
		}
		for _, p := range all {
			switch p.State {
			case "STOPPED", "CREATE_FAILED", "UPDATE_FAILED", "START_FAILED":
				continue
			}
			job := scheduler.Job{Key: p.ID, Version: uint64(p.Version), Due: p.Due}
			if !found || scheduler.Compare(job, next) < 0 {
				next, found = job, true
			}
		}
		return nil
	})
	return next, found, err
}
func (j pipeJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var p PipeRecord
	var work []Work
	var checkpoints []Checkpoint
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		p, err = r.PipeByID(job.Key)
		if err != nil {
			return err
		}
		if p.Version != int64(job.Version) || p.Due.After(s.clock.Now()) {
			return nil
		}
		work, err = r.Work(p.ID)
		if err != nil {
			return err
		}
		checkpoints, err = r.Checkpoints(p.ID)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.Version != int64(job.Version) || p.Due.After(s.clock.Now()) {
		return nil
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: p.Key.Partition, AccountID: p.Key.AccountID, Region: p.Key.Region, ParentEventID: p.ParentEventID})
	if err = s.recoverEffects(ctx, p, work); err != nil {
		return err
	}
	switch p.State {
	case "DELETING":
		s.closeSubscriptions(p.ID)
		if s.hasEffects(p.ID) {
			return s.delay(ctx, p, "")
		}
		if isKafka(p.Source.Kind) {
			if err := s.closeKafka(p.ID); err != nil {
				return s.delay(ctx, p, err.Error())
			}
			if s.kafkaSources == nil {
				return s.delay(ctx, p, "Kafka source adapter is unavailable.")
			}
			if err := s.kafkaSources.Delete(ctx, p); err != nil {
				return s.delay(ctx, p, err.Error())
			}
		}
		return s.repository.Update(ctx, func(t Transaction) error {
			v, err := t.PipeByID(p.ID)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if v.Version != p.Version {
				return nil
			}
			return t.DeletePipe(v.Key)
		})
	case "STOPPING":
		s.closeSubscriptions(p.ID)
		if s.hasEffects(p.ID) {
			return s.delay(ctx, p, "")
		}
		return s.finishStopped(ctx, p)
	case "CREATING", "STARTING", "UPDATING":
		s.closeSubscriptions(p.ID)
		if s.hasEffects(p.ID) {
			return s.delay(ctx, p, "")
		}
		if err := s.closeKafka(p.ID); err != nil {
			return s.delay(ctx, p, err.Error())
		}
		if err = s.checkSource(ctx, p); err != nil {
			state := "CREATE_FAILED"
			if p.State == "STARTING" {
				state = "START_FAILED"
			}
			if p.State == "UPDATING" {
				state = "UPDATE_FAILED"
			}
			return s.finishState(ctx, p, state, err.Error())
		}
		if p.Desired == "STOPPED" {
			return s.finishStopped(ctx, p)
		}
		return s.finishState(ctx, p, p.Desired, "")
	case "RUNNING":
	default:
		return nil
	}
	if err = s.checkSource(ctx, p); err != nil {
		var wire *awswire.Error
		if errors.As(err, &wire) && wire.StatusCode == 501 {
			s.closeSubscriptions(p.ID)
			return s.finishState(ctx, p, "STOPPED", wire.Message)
		}
		return s.delay(ctx, p, err.Error())
	}
	p, err = s.open(ctx, p)
	if err != nil {
		return s.delay(ctx, p, err.Error())
	}
	if isKafka(p.Source.Kind) {
		work, err = s.kafkaWork(ctx, p, work)
		if err != nil {
			return s.delay(ctx, p, err.Error())
		}
	}
	ack := acknowledgeable(p, work, s.clock.Now())
	if len(ack) > 0 {
		return s.ack(ctx, p, ack, checkpoints)
	}
	dead := []Work{}
	for _, w := range work {
		if w.Phase == "dlq" && !w.Due.After(s.clock.Now()) {
			dead = append(dead, w)
			if len(dead) == 10 {
				break
			}
		}
	}
	if len(dead) > 0 {
		return s.deadLetter(ctx, p, dead)
	}
	if batch := selectBatch(p, work, s.clock.Now()); len(batch) > 0 {
		return s.launch(ctx, p, batch)
	}
	return s.acquire(ctx, p, work, checkpoints)
}

// Once target effects have drained, settle their source acknowledgments before
// reporting STOPPED. Read again after the effect check: a completion can commit
// between the job's initial snapshot and removal from the in-flight effect set.
// Unexecuted and failed records remain retained; this path never polls or invokes.
func (s *Service) finishStopped(ctx context.Context, p PipeRecord) error {
	var work []Work
	var checkpoints []Checkpoint
	if err := s.repository.View(ctx, func(reader Reader) error {
		var err error
		work, err = reader.Work(p.ID)
		if err != nil {
			return err
		}
		checkpoints, err = reader.Checkpoints(p.ID)
		return err
	}); err != nil {
		return err
	}
	now := s.clock.Now()
	latest := now
	for _, record := range work {
		if record.Due.After(latest) {
			latest = record.Due
		}
	}
	pending := acknowledgeable(p, work, latest)
	if isKafka(p.Source.Kind) && len(pending) > 0 {
		var err error
		work, err = s.kafkaWork(ctx, p, work)
		if err != nil {
			return s.delay(ctx, p, err.Error())
		}
		pending = acknowledgeable(p, work, latest)
	}
	if ack := acknowledgeable(p, work, now); len(ack) > 0 {
		return s.ack(ctx, p, ack, checkpoints)
	}
	// Retriable acknowledgments must also drain. For streams, only an eligible
	// contiguous prefix can advance: successful records behind an earlier
	// failed/unexecuted record remain durable until a subsequent StartPipe.
	if len(pending) > 0 {
		return s.delay(ctx, p, "")
	}
	if err := s.closeKafka(p.ID); err != nil {
		return s.delay(ctx, p, err.Error())
	}
	return s.finishState(ctx, p, "STOPPED", "")
}
func (s *Service) finishState(ctx context.Context, p PipeRecord, state, reason string) error {
	return s.repository.Update(ctx, func(t Transaction) error {
		v, err := t.PipeByID(p.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Version != p.Version {
			return nil
		}
		v.State, v.Reason, v.Due = state, reason, s.clock.Now()
		return t.PutPipe(v)
	})
}
func (s *Service) checkSource(ctx context.Context, p PipeRecord) error {
	if isKafka(p.Source.Kind) {
		c, err := s.kafkaConsumer(ctx, p)
		if err != nil {
			return err
		}
		_, err = c.Assignments(ctx)
		return err
	}
	if s.sources == nil {
		return unsupported("Pipes requires a real configured source consumer.")
	}
	switch p.Source.Kind {
	case "sqs":
		c, err := s.sources.SQS(ctx, p)
		if err != nil {
			return err
		}
		info, err := c.Check(ctx)
		if err != nil {
			return err
		}
		if info.VisibilitySeconds < int(p.Source.WindowSeconds) {
			return invalid("Queue visibility timeout must exceed the batching window.")
		}
	case "kinesis":
		c, err := s.sources.Kinesis(ctx, p)
		if err != nil {
			return err
		}
		if _, err = c.Check(ctx); err != nil {
			return err
		}
	case "dynamodb":
		c, err := s.sources.DynamoDB(ctx, p)
		if err != nil {
			return err
		}
		if _, err = c.Check(ctx); err != nil {
			return err
		}
	default:
		return unsupported("No real consumer for this source.")
	}
	return nil
}
func selectBatch(p PipeRecord, work []Work, now time.Time) []Work {
	for _, first := range work {
		if first.Phase != "ready" {
			continue
		}
		limit := int(p.Source.BatchSize)
		if first.BatchLimit > 0 {
			limit = min(limit, int(first.BatchLimit))
		}
		var batch []Work
		size := 0
		blocked := false
		for _, w := range work {
			if !sameLane(p, first, w) {
				continue
			}
			if w.Ordinal < first.Ordinal && w.Phase != "ack" {
				// Standard SQS messages retry independently after queue visibility.
				if p.Source.Kind != "sqs" || stringsFIFO(p) || w.Phase != "waiting" {
					blocked = true
					break
				}
			}
			if w.Phase != "ready" {
				if len(batch) > 0 {
					break
				}
				continue
			}
			if w.Due.After(now) && (w.Attempts > 0 || w.LastError != "") {
				break
			}
			if len(batch) > 0 && size+len(w.Event) > 6*1024*1024 {
				break
			}
			batch = append(batch, w)
			size += len(w.Event)
			if len(batch) >= limit {
				break
			}
		}
		if blocked || len(batch) == 0 {
			continue
		}
		if first.Due.After(now) && len(batch) < limit && size < 6*1024*1024 {
			continue
		}
		return batch
	}
	return nil
}
func sameLane(p PipeRecord, a, b Work) bool {
	if p.Source.Kind == "sqs" {
		return !stringsFIFO(p) || a.GroupID == b.GroupID
	}
	if a.ShardID != b.ShardID {
		return false
	}
	if p.Source.Parallelism <= 1 {
		return true
	}
	return lane(a.GroupID, p.Source.Parallelism) == lane(b.GroupID, p.Source.Parallelism)
}
func lane(key string, count int32) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(key))
	return hash.Sum32() % uint32(count)
}
func stringsFIFO(p PipeRecord) bool {
	return strings.HasSuffix(p.SourceARN, ".fifo")
}
func acknowledgeable(p PipeRecord, work []Work, now time.Time) []Work {
	out := []Work{}
	blocked := map[string]bool{}
	for _, w := range work {
		if p.Source.Kind != "sqs" {
			if blocked[w.ShardID] {
				continue
			}
			if w.Phase != "ack" || w.Due.After(now) {
				blocked[w.ShardID] = true
				continue
			}
		}
		if w.Phase == "ack" && !w.Due.After(now) {
			out = append(out, w)
			if len(out) == 10 {
				break
			}
		}
	}
	return out
}
func (s *Service) delay(ctx context.Context, p PipeRecord, reason string) error {
	return s.repository.Update(ctx, func(t Transaction) error {
		v, err := t.PipeByID(p.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Version != p.Version {
			return nil
		}
		now := s.clock.Now()
		v.Due = now.Add(time.Second)
		if reason != "" {
			v.Reason = reason
		}
		if v.State == "RUNNING" && !isKafka(v.Source.Kind) {
			rows, err := t.Work(p.ID)
			if err != nil {
				return err
			}
			v.Due = workDue(v, rows, now)
		} else if reason == "" && v.Desired == "STOPPED" {
			// A target may finish between hasEffects and this transaction.
			// Preserve its immediate drain wake, but never bypass the backoff
			// when the acknowledgment itself failed.
			rows, err := t.Work(p.ID)
			if err != nil {
				return err
			}
			if len(acknowledgeable(v, rows, now)) > 0 {
				v.Due = now
			}
		}
		return t.PutPipe(v)
	})
}

// Source acquisition can race a target completion outside the repository
// transaction. Both idle paths derive their wake from the latest retained work
// so neither overwrites a just-committed acknowledgement with a polling delay.
func workDue(p PipeRecord, rows []Work, now time.Time) time.Time {
	if len(acknowledgeable(p, rows, now)) > 0 || len(selectBatch(p, rows, now)) > 0 {
		return now
	}
	for _, row := range rows {
		if row.Phase == "dlq" && !row.Due.After(now) {
			return now
		}
	}
	return now.Add(time.Second)
}
