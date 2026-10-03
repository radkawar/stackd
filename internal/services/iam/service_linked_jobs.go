package iam

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

type serviceLinkedDeletionJobs struct{ service *Service }

// This is an instance execution bound, not an AWS role or deletion-task quota.
const maxConcurrentServiceLinkedChecks = 16

func (source serviceLinkedDeletionJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	if err := ctx.Err(); err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	pending := make(map[string]struct{})
	runtime := source.service.serviceLinked
	runtime.mu.Lock()
	full := len(runtime.inflight) >= maxConcurrentServiceLinkedChecks
	runtime.mu.Unlock()
	if full {
		return scheduler.Job{}, false, nil
	}
	err := source.service.repository.View(ctx, func(tx ReadTx) error {
		scopes, err := tx.ServiceLinkedRoleDeletionScopes()
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			jobs, err := tx.ServiceLinkedRoleDeletions(scope)
			if err != nil {
				return err
			}
			for _, record := range jobs {
				if !serviceLinkedPending(record.Status) {
					continue
				}
				// Task IDs are immutable and never reused. The deletion callback
				// also fences the role's immutable ID before changing resources.
				job := scheduler.Job{Key: scope.Partition + "\x00" + scope.AccountID + "\x00" + record.ID, Version: 1, Due: record.CreatedAt}
				pending[job.Key] = struct{}{}
				runtime.mu.Lock()
				_, running := runtime.inflight[job.Key]
				retry, retrying := runtime.retryAt[job.Key]
				runtime.mu.Unlock()
				if running {
					continue
				}
				if retrying && retry.After(job.Due) {
					job.Due = retry
				}
				if !found || scheduler.Compare(job, next) < 0 {
					next, found = job, true
				}
			}
		}
		return nil
	})
	if err == nil {
		runtime.mu.Lock()
		for key := range runtime.retryAt {
			if _, exists := pending[key]; !exists {
				delete(runtime.retryAt, key)
			}
		}
		runtime.mu.Unlock()
	}
	return next, found, err
}

func (source serviceLinkedDeletionJobs) Run(ctx context.Context, job scheduler.Job) error {
	parts := strings.SplitN(job.Key, "\x00", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return errors.New("invalid service-linked deletion job scope")
	}
	if job.Version != 1 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := source.service
	runtime := s.serviceLinked
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return scheduler.ErrClosed
	}
	if _, running := runtime.inflight[job.Key]; running {
		runtime.mu.Unlock()
		return nil
	}
	if len(runtime.inflight) >= maxConcurrentServiceLinkedChecks {
		runtime.mu.Unlock()
		return nil
	}
	now := s.clock.Now()
	if retry, exists := runtime.retryAt[job.Key]; exists && retry.After(now) {
		runtime.mu.Unlock()
		return nil
	}
	// Registration and shutdown share this mutex: once Close begins, no Add
	// can race with its Wait. The callback's context belongs to the service,
	// not RunDue's short-lived drain context.
	runtime.inflight[job.Key] = struct{}{}
	runtime.checks.Add(1)
	runtime.mu.Unlock()
	retryAfter := now.Add(time.Second)
	go func() {
		defer runtime.checks.Done()
		err := s.processServiceLinkedRoleDeletion(runtime.ctx, Scope{Partition: parts[0], AccountID: parts[1]}, parts[2])
		runtime.mu.Lock()
		delete(runtime.inflight, job.Key)
		if err != nil && !errors.Is(err, ErrRecordNotFound) && !runtime.closed {
			// A failed IAM transaction leaves durable pending/in-progress work.
			// Delay its next eligibility rather than redispatching a failed job
			// repeatedly in the same bounded scheduler drain.
			runtime.retryAt[job.Key] = retryAfter
		} else {
			delete(runtime.retryAt, job.Key)
		}
		wake := !runtime.closed
		runtime.mu.Unlock()
		if wake {
			s.jobs.Wake()
		}
	}()
	return nil
}
