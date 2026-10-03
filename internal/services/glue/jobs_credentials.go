package glue

import (
	"context"
	"errors"

	runtime "stackd/compute/glue"
)

func (s *Service) bindJobCredentials(ctx context.Context, run JobRunRecord) error {
	if s.jobRuntime == nil || s.jobDependencies == nil {
		return errors.New("glue runtime dependencies are not configured")
	}
	return s.jobRuntime.SetCredentials(ctx, run.ExecutionKey(), func(ctx context.Context) (runtime.Credentials, error) {
		var current JobRunRecord
		err := s.repository.View(ctx, func(tx Reader) error { var err error; current, err = tx.GetJobRun(run.Key, run.ID); return err })
		if err != nil {
			return runtime.Credentials{}, err
		}
		if !current.Active() || current.State == "STOPPING" || current.RetryPending || current.Attempt != run.Attempt {
			return runtime.Credentials{}, errors.New("glue execution is no longer active")
		}
		return s.jobDependencies.Credentials(ctx, current)
	})
}
func (s *Service) recoverJobs(ctx context.Context) error {
	var runs []JobRunRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; runs, err = tx.PendingJobRuns(); return err }); err != nil {
		return err
	}
	for _, run := range runs {
		if run.Active() && run.LaunchAttempted && !run.RetryPending && run.State != "STOPPING" {
			if err := s.bindJobCredentials(ctx, run); err != nil {
				return err
			}
		}
	}
	return nil
}
