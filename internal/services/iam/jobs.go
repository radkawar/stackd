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
	s.startActivityWorker()
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

// Close joins accepted jobs and service-linked checks, then stops reporting work
// and durably flushes activity before repository shutdown. Repeated calls return
// the same shutdown result, including any final reporting failure.
func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		r := s.serviceLinked
		r.mu.Lock()
		r.closed = true
		r.cancel()
		r.mu.Unlock()
		s.jobs.Close()
		r.checks.Wait()
		s.closeErr = s.closeActivity()
	})
	return s.closeErr
}

// Wake only after the outer transaction commits. Persisted records remain the
// source of truth when a notification is coalesced or the process is interrupted.
func (s *Service) wakeJobs() {
	s.StartWorkers()
	s.jobs.Wake()
}
