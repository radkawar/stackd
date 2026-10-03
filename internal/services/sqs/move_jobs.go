package sqs

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// JobDriver exposes this service's scheduler for instance assembly. Join it
// before StartWorkers; joined services share execution and shutdown.
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

// StartWorkers recovers accepted redrive tasks after dependencies are wired.
func (s *Service) StartWorkers() { s.jobs.Start() }

// Close cancels and joins key preparation, redrive execution and long polls
// without canceling accepted AWS tasks. Storage and the clock remain caller-owned.
func (s *Service) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.stop()
	}
	s.mu.Unlock()
	s.jobs.Close()
	s.effects.Wait()
	s.polls.Wait()
	return nil
}

type moveJobs struct{ service *Service }

func moveJob(task MoveTaskRecord) scheduler.Job {
	return scheduler.Job{Key: fmt.Sprintf("%020d/%s", task.Sequence, task.Handle), Due: task.Due}
}

func movePending(task MoveTaskRecord) bool {
	return task.Status == moveRunning || task.Status == moveCancelling
}

func (source moveJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := source.service.repository.View(ctx, func(r Reader) error {
		tasks, err := r.MoveTasks()
		if err != nil {
			return err
		}
		for _, task := range tasks {
			if !movePending(task) {
				continue
			}
			candidate := moveJob(task)
			if !found || scheduler.Compare(candidate, next) < 0 {
				next, found = candidate, true
			}
		}
		return nil
	})
	return next, found, err
}

func (source moveJobs) Run(ctx context.Context, selected scheduler.Job) error {
	s := source.service
	_, handle, _ := strings.Cut(selected.Key, "/")
	var task MoveTaskRecord
	err := s.repository.View(ctx, func(r Reader) error {
		tasks, err := r.MoveTasks()
		if err != nil {
			return err
		}
		for _, candidate := range tasks {
			if candidate.Handle == handle {
				task = candidate
				break
			}
		}
		return nil
	})
	if err != nil || !selectedMove(&task, selected) || selected.Due.After(s.clock.Now()) {
		return err
	}
	if task.Status == moveCancelling {
		return s.finishMove(ctx, selected, moveCancelled, "")
	}
	// Admission used direct caller permissions. Execution is SQS forwarding
	// that same caller, and does not reissue StartMessageMoveTask.
	caller := awsctx.WithViaService(awsctx.WithMetadata(ctx, task.Caller), "sqs.amazonaws.com")
	r, err := http.NewRequestWithContext(caller, http.MethodPost, "http://localhost/", nil)
	if err != nil {
		return err
	}
	in := &api.StartMessageMoveTaskInput{SourceArn: str(privateKey(task.Source).arn()), DestinationArn: str(task.Destination)}
	wire := s.authorizedUpdate(r, moveDelivery, in, nil, func(r *http.Request) *awswire.Error {
		current := s.tasks[handle]
		if !selectedMove(current, selected) || current.Status != moveRunning {
			return nil
		}
		return s.advanceMove(r, current)
	})
	if wire == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if wire.StatusCode >= 500 {
		// Failed storage/dependency commits retain the accepted intent. The
		// shared driver retries in service time; shutdown is not AWS cancellation.
		return wire
	}
	reason := wire.Code + ": " + wire.Message
	if wire.Code == "AccessDenied" {
		reason = wire.Code
	}
	return s.finishMove(ctx, selected, moveFailed, reason)
}

func selectedMove(task *MoveTaskRecord, selected scheduler.Job) bool {
	return task != nil && movePending(*task) && moveJob(*task) == selected
}

func (s *Service) finishMove(ctx context.Context, selected scheduler.Job, status, reason string) error {
	_, handle, _ := strings.Cut(selected.Key, "/")
	return s.updateState(ctx, func() {
		if task := s.tasks[handle]; selectedMove(task, selected) {
			if task.Status == moveCancelling {
				task.Status, task.Failure = moveCancelled, ""
			} else {
				task.Status, task.Failure = status, reason
			}
		}
	})
}

func (s *Service) advanceMove(r *http.Request, task *MoveTaskRecord) *awswire.Error {
	q := s.lookupQueue(privateKey(task.Source))
	if q == nil || q.id != task.SourceID {
		task.Status, task.Failure = moveFailed, "The source queue was deleted."
		return nil
	}
	s.loadMessages(q)
	now := s.now()
	expires := task.Started.Add(36 * time.Hour)
	if !now.Before(expires) {
		task.Status, task.Failure = moveFailed, "The message move task exceeded 36 hours."
		return nil
	}
	if len(q.messages) == 0 {
		task.Status = moveCompleted
		return nil
	}
	candidates := q.availableMessages(now)
	if len(candidates) == 0 {
		next := now.Add(time.Second)
		if expires.Before(next) {
			next = expires
		}
		task.Due = s.nextWake(q, next)
		return nil
	}
	m := candidates[0]
	destination := task.Destination
	if destination == "" {
		destination = m.sourceARN
	}
	key, ok := parseQueueARN(destination)
	target := s.lookupQueue(key)
	if !ok || target == nil {
		task.Status, task.Failure = moveFailed, "The message has no available original source queue."
		return nil
	}
	delivered, err := s.moveOne(r, q, target, m)
	if err != nil {
		return err
	}
	if delivered {
		task.Moved++
	}
	// Do not accumulate rate credit while a message was delayed or invisible.
	// Due retains progress across drains; processing does not require another
	// manual advance for every elapsed message interval.
	if m.available.After(task.Due) {
		task.Due = m.available
	}
	task.Due = task.Due.Add(time.Second / time.Duration(task.Rate))
	if len(q.messages) == 0 {
		task.Status = moveCompleted
	}
	// TODO: Comeback capture optimized redrive rates, native startup/cancellation/36-hour timing, forwarding after reported completion and remaining network/partition forwarding conformance; finish durable scheduling and cross-service event recovery.
	return nil
}
