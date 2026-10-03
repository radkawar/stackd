package glue

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	runtime "stackd/compute/glue"
	"stackd/internal/scheduler"
)

type JobEvents interface {
	PublishJob(context.Context, JobRunRecord) error
}

type jobRunJobs struct{ s *Service }

func (j jobRunJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var selected scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(reader Reader) error {
		runs, err := reader.PendingJobRuns()
		if err != nil {
			return err
		}
		for _, run := range runs {
			candidate := scheduler.Job{Key: run.ExecutionKey(), Version: run.Version, Due: run.NextAttempt}
			if !found || scheduler.Compare(candidate, selected) < 0 {
				selected = candidate
				found = true
			}
		}
		return nil
	})
	return selected, found, err
}
func (j jobRunJobs) Run(ctx context.Context, selected scheduler.Job) error {
	s := j.s
	var run JobRunRecord
	found, launch := false, false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		runs, err := tx.PendingJobRuns()
		if err != nil {
			return err
		}
		for _, candidate := range runs {
			if candidate.ExecutionKey() == selected.Key && candidate.Version == selected.Version {
				run = candidate
				found = true
				break
			}
		}
		if !found {
			return nil
		}
		if run.Active() && !run.RetryPending && run.State != "STOPPING" && !s.clock.Now().Before(run.StartedAt.Add(time.Duration(run.Timeout)*time.Minute)) {
			run.State = "STOPPING"
			run.Error = "Job exceeded its configured timeout"
			run.Version++
			run.UpdatedAt = s.clock.Now()
			if err := tx.PutJobRun(run); err != nil {
				return err
			}
		}
		if run.State == "STARTING" && !run.LaunchAttempted && !run.RetryPending {
			// One native slot bounds aggregate local memory independently of the
			// caller's admitted per-job concurrency limit.
			for _, other := range runs {
				if other.ID != run.ID && other.Active() && other.LaunchAttempted {
					run.NextAttempt = s.clock.Now().Add(time.Second)
					run.Version++
					found = false
					return tx.PutJobRun(run)
				}
			}
			run.LaunchAttempted = true
			run.Version++
			run.NextAttempt = s.clock.Now().Add(time.Second)
			launch = true
			return tx.PutJobRun(run)
		}
		return nil
	})
	if err != nil || !found {
		return err
	}
	if s.jobRuntime == nil {
		return j.finish(ctx, run, "ERROR", "Execution runtime is not configured", runtime.Status{})
	}
	if run.Active() && run.State != "STOPPING" && !run.RetryPending {
		if err := s.bindJobCredentials(ctx, run); err != nil {
			return err
		}
	}
	if launch {
		job := JobRecord{Key: run.Key, Role: run.Role, Command: run.Command, ScriptLocation: run.ScriptLocation, PythonVersion: run.PythonVersion, GlueVersion: run.GlueVersion, SecurityConfiguration: run.SecurityConfiguration, Timeout: run.Timeout}
		input, err := s.jobDependencies.Prepare(ctx, job, run)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return j.finish(ctx, run, "FAILED", err.Error(), runtime.Status{})
		}
		args := maps.Clone(run.Arguments)
		args["--JOB_NAME"] = run.Key.Name
		args["--JOB_RUN_ID"] = run.ID
		if run.WorkflowName != "" {
			args["--WORKFLOW_NAME"] = run.WorkflowName
			args["--WORKFLOW_RUN_ID"] = run.WorkflowRunID
		}
		err = s.jobRuntime.Start(ctx, runtime.Execution{Key: run.ExecutionKey(), Command: run.Command, Region: run.Key.Region, Script: input.Script, Environment: input.Environment, Arguments: args, S3EncryptionMode: run.S3EncryptionMode, S3KMSKeyARN: run.S3KMSKeyARN})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if stopErr := s.jobRuntime.Stop(ctx, run.ExecutionKey()); stopErr != nil {
				return stopErr
			}
			return j.finish(ctx, run, "FAILED", err.Error(), runtime.Status{})
		}
		// A cancellation/deletion committed during native launch wins. Its own
		// retained worker will stop the newly created process.
		return j.update(ctx, run, func(current *JobRunRecord) {
			current.State = "RUNNING"
			current.NextAttempt = s.clock.Now().Add(time.Second)
		})
	}
	if run.State == "STOPPING" {
		if err := s.jobRuntime.Stop(ctx, run.ExecutionKey()); err != nil {
			return err
		}
		state, message := "STOPPED", run.Error
		if message == "Job exceeded its configured timeout" {
			state = "TIMEOUT"
		}
		status, err := s.jobRuntime.Inspect(ctx, run.ExecutionKey())
		if err != nil {
			return err
		}
		if status.Running {
			return j.update(ctx, run, func(current *JobRunRecord) { current.NextAttempt = s.clock.Now().Add(time.Second) })
		}
		return j.finish(ctx, run, state, message, status)
	}
	if run.Active() && !run.RetryPending {
		status, err := s.jobRuntime.Inspect(ctx, run.ExecutionKey())
		if err != nil {
			return err
		}
		if !status.Found {
			return j.finish(ctx, run, "ERROR", "Execution lost after controller restart; customer code was not replayed", runtime.Status{})
		}
		if status.Running {
			return j.update(ctx, run, func(current *JobRunRecord) {
				current.State = "RUNNING"
				current.NextAttempt = s.clock.Now().Add(time.Second)
			})
		}
		state, message := "SUCCEEDED", status.Error
		if status.ExitCode != 0 {
			state = "FAILED"
			if message == "" {
				message = fmt.Sprintf("Process exited with code %d", status.ExitCode)
			}
		}
		return j.finish(ctx, run, state, message, status)
	}
	if !run.MetricsPublished {
		return s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.GetJobRun(run.Key, run.ID)
			if err != nil {
				return err
			}
			if current.Version != run.Version {
				return nil
			}
			if s.jobDependencies != nil {
				if err := s.jobDependencies.PublishMetrics(tx.Context(), current); err != nil {
					return err
				}
			}
			current.MetricsPublished = true
			current.Version++
			return tx.PutJobRun(current)
		})
	}
	if !run.Published {
		var publicationErr error
		if s.jobDependencies != nil {
			publicationErr = s.jobDependencies.Publish(ctx, run, run.Output)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Native logging failure must not prevent a configured job retry or change
		// the actual process outcome. Retain the reason with the captured bytes.
		return j.update(ctx, run, func(current *JobRunRecord) {
			current.Published = true
			if publicationErr != nil {
				if current.LogError != "" {
					current.LogError += "; "
				}
				current.LogError += publicationErr.Error()
			}
			current.NextAttempt = s.clock.Now()
		})
	}
	if run.CleanupPending {
		if err := s.jobRuntime.Remove(ctx, run.ExecutionKey()); err != nil {
			return err
		}
		return j.update(ctx, run, func(current *JobRunRecord) { current.CleanupPending = false })
	}
	if run.RetryPending {
		return j.update(ctx, run, func(current *JobRunRecord) {
			current.Attempt++
			current.State = "STARTING"
			current.RetryPending = false
			current.LaunchAttempted = false
			current.Published = false
			current.MetricsPublished = false
			current.Error = ""
			current.Output = ""
			current.ErrorOutput = ""
			current.LogError = ""
			current.SparkMetrics = runtime.SparkMetrics{}
			current.StartedAt = s.clock.Now()
			current.CompletedAt = time.Time{}
			current.NextAttempt = s.clock.Now()
		})
	}
	return nil
}
func (j jobRunJobs) update(ctx context.Context, expected JobRunRecord, mutate func(*JobRunRecord)) error {
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.GetJobRun(expected.Key, expected.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != expected.Version {
			return nil
		}
		oldState := current.State
		mutate(&current)
		current.Version++
		current.UpdatedAt = j.s.clock.Now()
		if err := tx.PutJobRun(current); err != nil {
			return err
		}
		if oldState != current.State && j.s.jobEvents != nil {
			return j.s.jobEvents.PublishJob(tx.Context(), current)
		}
		return nil
	})
}
func (j jobRunJobs) finish(ctx context.Context, run JobRunRecord, state, message string, status runtime.Status) error {
	return j.update(ctx, run, func(current *JobRunRecord) {
		current.State = state
		current.Error = message
		current.Output = status.Output
		current.ErrorOutput = status.ErrorOutput
		current.LogError = status.ObservationError
		current.SparkMetrics = status.SparkMetrics
		current.CompletedAt = j.s.clock.Now()
		current.NextAttempt = j.s.clock.Now()
		current.CleanupPending = current.LaunchAttempted
		current.RetryPending = false
		current.ExecutionSeconds = status.ExecutionSeconds
		current.Attempts = append(current.Attempts, JobAttemptRecord{Attempt: current.Attempt, State: state, Error: message, Output: status.Output, ErrorOutput: status.ErrorOutput, StartedAt: current.StartedAt, CompletedAt: current.CompletedAt})
		if state == "FAILED" && current.Attempt < current.MaxRetries {
			current.State = "STARTING"
			current.RetryPending = true
		}
	})
}
