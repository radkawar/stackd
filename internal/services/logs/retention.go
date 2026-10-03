package logs

import (
	"context"
	"stackd/internal/scheduler"
)

// Deletion runs separately from policy updates. AWS's variable physical deletion
// latency is not modeled; the worker rechecks current retention at commit time.
type retentionJobs struct{ s *Service }

func (j retentionJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error {
		job, found, err = r.NextRetention()
		return err
	})
	return
}

func (j retentionJobs) Run(ctx context.Context, _ scheduler.Job) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		return tx.ExpireEvents(j.s.clock.Now().UnixMilli())
	})
}
