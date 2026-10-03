package xray

import (
	"context"
	"time"

	"stackd/internal/scheduler"
)

func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

func (s *Service) Close() error {
	s.jobs.Close()
	return nil
}

type traceExpiry struct{ s *Service }

func (j traceExpiry) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var due time.Time
	var found bool
	err := j.s.repository.View(ctx, func(r Reader) error {
		for _, source := range []struct {
			earliest  func() (time.Time, bool, error)
			retention time.Duration
		}{
			{r.EarliestSegmentReceipt, traceRetention},
			{r.EarliestSamplingReceipt, samplingLease},
		} {
			at, exists, err := source.earliest()
			if err != nil {
				return err
			}
			if candidate := at.Add(source.retention); exists && (!found || candidate.Before(due)) {
				due, found = candidate, true
			}
		}
		return nil
	})
	return scheduler.Job{Key: "expired-xray-state", Due: due}, found, err
}

func (j traceExpiry) Run(ctx context.Context, _ scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		now := j.s.clock.Now()
		if err := tx.DeleteExpiredSegments(now.Add(-traceRetention)); err != nil {
			return err
		}
		return tx.DeleteExpiredSamplingState(now.Add(-samplingLease))
	})
}
