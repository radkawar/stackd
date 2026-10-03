package iam

import (
	"context"

	"stackd/internal/scheduler"
)

// JobDriver exposes this service's scheduler for instance assembly. Join it
// before StartWorkers; joined services share execution and shutdown.
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

// StartWorkers starts IAM's shared persisted-job driver,
// including report generation and service-linked deletion recovery. Startup
// freezes service registrations. Close joins work before repository shutdown.
func (s *Service) StartWorkers() {
	r := s.serviceLinked
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.started = true
	s.jobs.Start()
}

// RunDueJobs processes or schedules at most limit intents due at the current
// service time, sharing execution with the automatic worker. Reports complete
// synchronously; service-linked-role usage checks run outside the drain and
// complete through their persisted task status. Deterministic scheduling ends
// at that external usage provider. This method does not advance service time.
func (s *Service) RunDueJobs(ctx context.Context, limit int) (scheduler.Result, error) {
	s.serviceLinked.mu.Lock()
	if s.serviceLinked.closed {
		s.serviceLinked.mu.Unlock()
		return scheduler.Result{}, scheduler.ErrClosed
	}
	s.serviceLinked.started = true
	s.serviceLinked.mu.Unlock()
	return s.jobs.RunDue(ctx, limit)
}

// Close stops IAM background work and waits for any transaction in flight.
// It is safe to call repeatedly, including before worker startup.
func (s *Service) Close() error {
	r := s.serviceLinked
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.mu.Unlock()
	s.jobs.Close()
	r.checks.Wait()
	return nil
}

// Wake only after the outer transaction commits. Persisted records remain the
// source of truth when a notification is coalesced or the process is interrupted.
func (s *Service) wakeJobs() {
	s.StartWorkers()
	s.jobs.Wake()
}
