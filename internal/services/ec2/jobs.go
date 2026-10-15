package ec2

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"stackd/internal/scheduler"
)

type computeJobs struct{ service *Service }

type computeEffects struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	work    sync.WaitGroup
	active  bool
	closed  bool
	retryAt time.Time
}

func (j computeJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	s := j.service
	s.compute.mu.Lock()
	available, retryAt := !s.compute.active && !s.compute.closed, s.compute.retryAt
	s.compute.mu.Unlock()
	var next time.Time
	found := false
	if available {
		var err error
		next, found, err = s.NextInstanceDeadline(ctx)
		if err != nil {
			return scheduler.Job{}, false, err
		}
		image, imageFound, err := s.NextImageDeadline(ctx)
		if err != nil {
			return scheduler.Job{}, false, err
		}
		if imageFound && (!found || image.Before(next)) {
			next, found = image, true
		}
		if found && next.Before(retryAt) {
			next = retryAt
		}
	}
	job := scheduler.Job{Key: "ec2-compute", Due: next}
	var association time.Time
	var associationFound bool
	err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		association, associationFound, err = tx.NextInstanceProfileAssociationDeadline()
		return err
	})
	if err != nil {
		return scheduler.Job{}, false, err
	}
	if associationFound && (!found || !association.After(next)) {
		job = scheduler.Job{Key: "ec2-instance-profile", Due: association}
		found = true
	}
	return job, found, nil
}

func (j computeJobs) Run(ctx context.Context, job scheduler.Job) error {
	if job.Key == "ec2-instance-profile" {
		_, err := j.service.AdvanceInstanceProfileAssociations(ctx)
		return err
	}
	j.service.dispatchCompute()
	return nil
}

// Persisted deadlines own recovery. Native disk and guest work must not hold
// the shared service-time drain while other API requests wait for that drain.
func (s *Service) dispatchCompute() {
	s.compute.mu.Lock()
	defer s.compute.mu.Unlock()
	if s.compute.closed || s.compute.active {
		return
	}
	if s.compute.ctx == nil {
		s.compute.ctx, s.compute.cancel = context.WithCancel(context.Background())
	}
	s.compute.active = true
	s.compute.work.Go(func() {
		ctx := s.compute.ctx
		_, err := s.AdvanceImages(ctx)
		if err == nil {
			_, err = s.AdvanceInstances(ctx)
		}
		if err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "EC2 native reconciliation failed", "error", err)
		}
		s.compute.mu.Lock()
		s.compute.active = false
		s.compute.retryAt = time.Time{}
		if err != nil && ctx.Err() == nil {
			// Keep the scheduler's existing one-second failure retry interval.
			s.compute.retryAt = s.clock.Now().Add(time.Second)
		}
		closed := s.compute.closed
		s.compute.mu.Unlock()
		if !closed {
			s.jobs.Wake()
		}
	})
}

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

func (s *Service) Close() error {
	s.compute.mu.Lock()
	s.compute.closed = true
	if s.compute.cancel != nil {
		s.compute.cancel()
	}
	s.compute.mu.Unlock()
	s.jobs.Close()
	s.compute.work.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.CloseInstanceControllers(ctx)
}
