package pipes

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	dynamodbapi "stackd/internal/awsapi/dynamodbstreams"
	"stackd/internal/awswire"
	"stackd/internal/services/lambda"
)

// The second scheduler selection sees executing work, then releases its read
// transaction and pauses. Only after the target has committed ack and removed
// its process-local effect does that selection continue into recovery. Writing
// the selected snapshot here used to revert ack to ready and launch the target
// twice; the first successful effect could no longer advance its checkpoint.
func TestRecoveryDoesNotRepeatCompletedTarget(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	repository := NewMemoryRepository(nil)
	gate := &recoverySnapshotRepository{Repository: repository, selected: make(chan struct{}), resume: make(chan struct{})}
	target := &recoveryTarget{entered: make(chan struct{}), release: make(chan struct{})}
	p, work, checkpoint := recoveryRecords(now)
	seedRecovery(t, repository, p, work, checkpoint)
	service := NewWithConfig(Config{Repository: gate, Clock: clock.NewManual(now), Sources: recoverySources{}, Targets: target})
	defer service.Close()
	defer gate.unblock()
	defer target.unblock()

	drained := make(chan error, 1)
	go func() {
		_, err := service.JobDriver().RunDue(ctx, 3)
		drained <- err
	}()
	awaitRecovery(t, ctx, target.entered)
	awaitRecovery(t, ctx, gate.selected)
	target.unblock()
	service.effectsDone.Wait()
	stored, checkpoints := recoveryState(t, repository, p.ID)
	if len(stored) != 1 || stored[0].Phase != "ack" || checkpoints[0].Sequence != checkpoint.Sequence || service.hasEffects(p.ID) {
		t.Fatalf("target did not finish before stale selection resumed: work=%+v checkpoints=%+v", stored, checkpoints)
	}
	gate.unblock()
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Join any erroneously relaunched target before checking its observable count.
	service.effectsDone.Wait()
	if _, err := service.JobDriver().RunDue(ctx, 3); err != nil {
		t.Fatal(err)
	}
	stored, checkpoints = recoveryState(t, repository, p.ID)
	if target.calls.Load() != 1 || len(stored) != 0 || len(checkpoints) != 1 || checkpoints[0].Sequence != work.Sequence {
		t.Fatalf("completed target was replayed or checkpoint lost: calls=%d work=%+v checkpoints=%+v", target.calls.Load(), stored, checkpoints)
	}
}

func TestRecoveryRevalidatesWorkAndPipeInTransaction(t *testing.T) {
	for _, transition := range []string{"ack", "checkpoint", "retry", "new-attempt", "version", "replacement", "rollback", "current"} {
		t.Run(transition, func(t *testing.T) {
			now := time.Unix(100, 0).UTC()
			repository := NewMemoryRepository(nil)
			p, original, checkpoint := recoveryRecords(now)
			original.Phase, original.Due = "executing", now.Add(5*time.Minute)
			seedRecovery(t, repository, p, original, checkpoint)
			stale := []Work{original}
			aborted := errors.New("recovery commit rejected")
			gate := &recoveryUpdateRepository{Repository: repository}
			gate.before = func() error {
				return repository.Update(t.Context(), func(tx Transaction) error {
					current := original
					switch transition {
					case "ack":
						current.Phase, current.Due = "ack", now
					case "checkpoint":
						checkpoint.Sequence = original.Sequence
						if err := tx.PutCheckpoint(checkpoint); err != nil {
							return err
						}
						return tx.DeleteWork(original.ID)
					case "retry":
						current.Phase, current.Due, current.Attempts = "ready", now.Add(2*time.Second), 1
						current.LastError = "target unavailable"
					case "new-attempt":
						current.Due, current.Attempts = original.Due.Add(time.Second), 1
					case "version":
						currentPipe := p
						currentPipe.Version++
						currentPipe.State = "STOPPING"
						return tx.PutPipe(currentPipe)
					case "replacement":
						if err := tx.DeletePipe(p.Key); err != nil {
							return err
						}
						currentPipe := p
						currentPipe.ID = "replacement"
						return tx.PutPipe(currentPipe)
					case "current":
						// Recovery must keep current retained fields, not stale bytes.
						current.Receipt = "renewed-receipt"
					}
					return tx.PutWork(current)
				})
			}
			if transition == "rollback" {
				gate.reject = aborted
			}
			service := NewWithConfig(Config{Repository: gate, Clock: clock.NewManual(now)})
			defer service.Close()
			err := service.recoverEffects(t.Context(), p, stale)
			if transition == "rollback" {
				if !errors.Is(err, aborted) {
					t.Fatalf("recovery commit error = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			stored, checkpoints := recoveryState(t, repository, p.ID)
			if transition == "current" {
				if len(stored) != 1 || stored[0].Phase != "ready" || !stored[0].Due.Equal(now) || stored[0].Receipt != "renewed-receipt" || !reflect.DeepEqual(stale, stored) {
					t.Fatalf("orphaned execution did not recover current work: selected=%+v stored=%+v", stale, stored)
				}
				return
			}
			if !reflect.DeepEqual(stale, []Work{original}) || len(selectBatch(p, stale, now)) != 0 {
				t.Fatalf("uncommitted recovery made stale work launchable: %+v", stale)
			}
			switch transition {
			case "checkpoint":
				if len(stored) != 0 || len(checkpoints) != 1 || checkpoints[0].Sequence != original.Sequence {
					t.Fatalf("acknowledged work resurrected: work=%+v checkpoints=%+v", stored, checkpoints)
				}
			case "replacement":
				if len(stored) != 0 {
					t.Fatalf("deleted pipe work resurrected: %+v", stored)
				}
			default:
				want := original
				if transition == "ack" {
					want.Phase, want.Due = "ack", now
				} else if transition == "retry" {
					want.Phase, want.Due, want.Attempts, want.LastError = "ready", now.Add(2*time.Second), 1, "target unavailable"
				} else if transition == "new-attempt" {
					want.Due, want.Attempts = original.Due.Add(time.Second), 1
				}
				if !reflect.DeepEqual(stored, []Work{want}) {
					t.Fatalf("recovery overwrote current work: got=%+v want=%+v", stored, want)
				}
			}
		})
	}
}

func TestRecoveryRetriesOrphanedExecution(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	source := clock.NewManual(now)
	repository := NewMemoryRepository(nil)
	p, original, checkpoint := recoveryRecords(now)
	original.Phase, original.Due = "executing", now.Add(5*time.Minute)
	seedRecovery(t, repository, p, original, checkpoint)
	target := &recoveryTarget{failure: failure("InternalException", "target unavailable", 500)}
	service := NewWithConfig(Config{Repository: repository, Clock: source, Sources: recoverySources{}, Targets: target})
	defer service.Close()
	// Manually drive the owner so asynchronous Wake cannot race assertions.
	service.JobDriver().Close()
	work := []Work{original}
	if err := service.recoverEffects(t.Context(), p, work); err != nil {
		t.Fatal(err)
	}
	batch := selectBatch(p, work, now)
	if len(batch) != 1 {
		t.Fatalf("orphaned execution is not retryable: %+v", work)
	}
	if err := service.launch(t.Context(), p, batch); err != nil {
		t.Fatal(err)
	}
	service.effectsDone.Wait()
	work, checkpoints := recoveryState(t, repository, p.ID)
	if len(work) != 1 || work[0].Phase != "ready" || work[0].Attempts != 1 || !work[0].Due.After(now) || checkpoints[0].Sequence != checkpoint.Sequence || len(selectBatch(p, work, now)) != 0 {
		t.Fatalf("real target failure lost retry/checkpoint boundary: work=%+v checkpoints=%+v", work, checkpoints)
	}
	if err := source.Advance(work[0].Due.Sub(source.Now())); err != nil {
		t.Fatal(err)
	}
	target.failure = nil
	batch = selectBatch(p, work, source.Now())
	if len(batch) != 1 {
		t.Fatalf("due retry not selected: %+v", work)
	}
	if err := service.launch(t.Context(), p, batch); err != nil {
		t.Fatal(err)
	}
	service.effectsDone.Wait()
	work, checkpoints = recoveryState(t, repository, p.ID)
	if len(work) != 1 || work[0].Phase != "ack" || target.calls.Load() != 2 {
		t.Fatalf("recovered retry did not complete: calls=%d work=%+v", target.calls.Load(), work)
	}
	if err := service.ack(t.Context(), p, work, checkpoints); err != nil {
		t.Fatal(err)
	}
	work, checkpoints = recoveryState(t, repository, p.ID)
	if len(work) != 0 || checkpoints[0].Sequence != original.Sequence {
		t.Fatalf("successful retry did not advance checkpoint: work=%+v checkpoints=%+v", work, checkpoints)
	}
}

func recoveryRecords(now time.Time) (PipeRecord, Work, Checkpoint) {
	p := PipeRecord{ID: "pipe", Version: 1, State: "RUNNING", Desired: "RUNNING", Due: now,
		Key:    Key{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "recovery"},
		Source: SourceSettings{Kind: "dynamodb", BatchSize: 1, Parallelism: 1, MaximumAge: -1, MaximumRetries: -1}}
	w := Work{ID: "work", PipeID: p.ID, RecordID: "record", ShardID: "shard", Sequence: "42", Ordinal: 1, Event: []byte(`{"value":"retained"}`), Created: now, Due: now, Phase: "ready"}
	cp := Checkpoint{PipeID: p.ID, ShardID: w.ShardID, Sequence: "41", Initialized: true, Closed: true}
	return p, w, cp
}

func seedRecovery(t *testing.T, repository Repository, p PipeRecord, w Work, cp Checkpoint) {
	t.Helper()
	if err := repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutPipe(p); err != nil {
			return err
		}
		if err := tx.PutCheckpoint(cp); err != nil {
			return err
		}
		return tx.PutWork(w)
	}); err != nil {
		t.Fatal(err)
	}
}

func recoveryState(t *testing.T, repository Repository, id string) ([]Work, []Checkpoint) {
	t.Helper()
	var work []Work
	var checkpoints []Checkpoint
	if err := repository.View(t.Context(), func(reader Reader) error {
		var err error
		work, err = reader.Work(id)
		if err != nil {
			return err
		}
		checkpoints, err = reader.Checkpoints(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return work, checkpoints
}

func awaitRecovery(t *testing.T, ctx context.Context, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

type recoverySnapshotRepository struct {
	Repository
	selected, resume       chan struct{}
	selectOnce, resumeOnce sync.Once
}

func (r *recoverySnapshotRepository) unblock() {
	r.resumeOnce.Do(func() { close(r.resume) })
}

func (r *recoverySnapshotRepository) View(ctx context.Context, f func(Reader) error) error {
	var selected bool
	err := r.Repository.View(ctx, func(reader Reader) error {
		return f(recoveryReader{Reader: reader, executing: &selected})
	})
	if err == nil && selected {
		r.selectOnce.Do(func() {
			close(r.selected)
			select {
			case <-r.resume:
			case <-ctx.Done():
				err = ctx.Err()
			}
		})
	}
	return err
}

type recoveryReader struct {
	Reader
	executing *bool
}

func (r recoveryReader) Work(id string) ([]Work, error) {
	work, err := r.Reader.Work(id)
	for _, w := range work {
		*r.executing = *r.executing || w.Phase == "executing"
	}
	return work, err
}

type recoveryUpdateRepository struct {
	Repository
	before func() error
	reject error
}

func (r *recoveryUpdateRepository) Update(ctx context.Context, f func(Transaction) error) error {
	if err := r.before(); err != nil {
		return err
	}
	return r.Repository.Update(ctx, func(tx Transaction) error {
		if err := f(tx); err != nil {
			return err
		}
		return r.reject
	})
}

type recoveryTarget struct {
	Targets
	calls            atomic.Int64
	entered, release chan struct{}
	releaseOnce      sync.Once
	failure          *awswire.Error
}

func (r *recoveryTarget) unblock() {
	r.releaseOnce.Do(func() { close(r.release) })
}

func (r *recoveryTarget) Deliver(ctx context.Context, _ PipeRecord, _ []Work, _ []TargetEvent, _ bool) (DeliveryResult, *awswire.Error) {
	if r.calls.Add(1) == 1 && r.entered != nil {
		close(r.entered)
		select {
		case <-r.release:
		case <-ctx.Done():
			return DeliveryResult{}, wireError(ctx.Err())
		}
	}
	return DeliveryResult{}, r.failure
}

type recoverySources struct {
	Sources
}

func (recoverySources) DynamoDB(context.Context, PipeRecord) (lambda.DynamoDBConsumer, *awswire.Error) {
	return recoveryStream{}, nil
}

type recoveryStream struct {
	lambda.DynamoDBConsumer
}

func (recoveryStream) Check(context.Context) (*dynamodbapi.StreamDescription, *awswire.Error) {
	return &dynamodbapi.StreamDescription{Shards: dynamodbapi.ShardDescriptionList{{ShardId: new(dynamodbapi.ShardId("shard"))}}}, nil
}
