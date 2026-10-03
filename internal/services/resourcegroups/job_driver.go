package resourcegroups

import (
	"context"
	"stackd/internal/scheduler"
)

type resourceGroupJobs struct{ service *Service }

func (j resourceGroupJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	return j.service.NextJob(ctx)
}
func (j resourceGroupJobs) Run(ctx context.Context, job scheduler.Job) error {
	return j.service.RunDue(ctx, job)
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error {
	if s.jobs != nil {
		s.jobs.Close()
	}
	return nil
}
