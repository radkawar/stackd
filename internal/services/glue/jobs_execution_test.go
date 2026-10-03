package glue

import (
	"context"
	"testing"
	"time"

	"stackd/clock"
	runtime "stackd/compute/glue"
	"stackd/internal/scheduler"
)

type jobTestRuntime struct {
	starts, stops int
	status        runtime.Status
	onStart       func() error
}

func (r *jobTestRuntime) SetCredentials(context.Context, string, runtime.CredentialProvider) error {
	return nil
}
func (r *jobTestRuntime) Start(context.Context, runtime.Execution) error {
	r.starts++
	if r.onStart != nil {
		return r.onStart()
	}
	return nil
}
func (r *jobTestRuntime) Inspect(context.Context, string) (runtime.Status, error) {
	return r.status, nil
}
func (r *jobTestRuntime) Stop(context.Context, string) error {
	r.stops++
	r.status.Running = false
	return nil
}
func (r *jobTestRuntime) Remove(context.Context, string) error { return nil }

type jobTestDependencies struct{}

func (jobTestDependencies) Credentials(context.Context, JobRunRecord) (runtime.Credentials, error) {
	return runtime.Credentials{}, nil
}
func (jobTestDependencies) PublishMetrics(context.Context, JobRunRecord) error { return nil }
func (jobTestDependencies) Prepare(context.Context, JobRecord, JobRunRecord) (JobExecutionInput, error) {
	return JobExecutionInput{Script: []byte("print(13)")}, nil
}
func (jobTestDependencies) Publish(context.Context, JobRunRecord, string) error { return nil }
func executionFixture(t *testing.T, run JobRunRecord, native *jobTestRuntime) (*Service, jobRunJobs) {
	t.Helper()
	repo := NewMemoryRepository(nil)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	if run.StartedAt.IsZero() {
		run.StartedAt = now
	}
	if run.Timeout == 0 {
		run.Timeout = 2
	}
	run.NextAttempt = now
	if err := repo.Update(t.Context(), func(tx Transaction) error { return tx.PutJobRun(run) }); err != nil {
		t.Fatal(err)
	}
	s := &Service{repository: repo, clock: clock.NewManual(now), jobRuntime: native, jobDependencies: jobTestDependencies{}}
	return s, jobRunJobs{s}
}
func executeOne(t *testing.T, source jobRunJobs) {
	t.Helper()
	job, ok, err := source.Next(t.Context())
	if err != nil || !ok {
		t.Fatalf("select: %v %v", ok, err)
	}
	if err := source.Run(t.Context(), job); err != nil {
		t.Fatal(err)
	}
}
func readTestRun(t *testing.T, s *Service, run JobRunRecord) JobRunRecord {
	t.Helper()
	var out JobRunRecord
	if err := s.repository.View(t.Context(), func(r Reader) error { var err error; out, err = r.GetJobRun(run.Key, run.ID); return err }); err != nil {
		t.Fatal(err)
	}
	return out
}
func TestJobLostExecutionNeverReplaysCustomerCode(t *testing.T) {
	run := JobRunRecord{Key: ResourceKey{Scope: Scope{"aws", "111111111111", "us-east-1"}, Name: "lost"}, ID: "jr_lost", State: "STARTING", Version: 2, LaunchAttempted: true}
	native := &jobTestRuntime{}
	s, source := executionFixture(t, run, native)
	executeOne(t, source)
	got := readTestRun(t, s, run)
	if got.State != "ERROR" || native.starts != 0 || got.CompletedAt.IsZero() {
		t.Fatalf("lost run replayed or remained active: %+v starts=%d", got, native.starts)
	}
}
func TestJobCancelDuringLaunchFencesStaleSuccess(t *testing.T) {
	run := JobRunRecord{Key: ResourceKey{Scope: Scope{"aws", "111111111111", "us-east-1"}, Name: "cancel"}, ID: "jr_cancel", State: "STARTING", Version: 1, Arguments: map[string]string{}}
	native := &jobTestRuntime{status: runtime.Status{Found: true, Running: true}}
	s, source := executionFixture(t, run, native)
	native.onStart = func() error {
		return s.repository.Update(t.Context(), func(tx Transaction) error {
			current, err := tx.GetJobRun(run.Key, run.ID)
			if err != nil {
				return err
			}
			current.State = "STOPPING"
			current.Version++
			return tx.PutJobRun(current)
		})
	}
	executeOne(t, source)
	if got := readTestRun(t, s, run); got.State != "STOPPING" {
		t.Fatalf("stale launch overwrote cancellation: %s", got.State)
	}
	executeOne(t, source)
	got := readTestRun(t, s, run)
	if got.State != "STOPPED" || native.stops != 1 {
		t.Fatalf("cancellation did not stop process: %+v stops=%d", got, native.stops)
	}
}
func TestJobProcessFailureRetainsSeparateOutput(t *testing.T) {
	run := JobRunRecord{Key: ResourceKey{Scope: Scope{"aws", "111111111111", "us-east-1"}, Name: "failure"}, ID: "jr_failure", State: "RUNNING", Version: 2, LaunchAttempted: true}
	native := &jobTestRuntime{status: runtime.Status{Found: true, ExitCode: 3, Output: "produced:13\n", ErrorOutput: "ValueError: intentional\n"}}
	s, source := executionFixture(t, run, native)
	executeOne(t, source)
	got := readTestRun(t, s, run)
	if got.State != "FAILED" || got.Output != "produced:13\n" || got.ErrorOutput != "ValueError: intentional\n" {
		t.Fatalf("incorrect process outcome: %+v", got)
	}
	if err := source.Run(t.Context(), scheduler.Job{Key: got.ExecutionKey(), Version: run.Version, Due: run.StartedAt}); err != nil {
		t.Fatal(err)
	}
	if after := readTestRun(t, s, run); after.State != "FAILED" || after.Version != got.Version {
		t.Fatalf("stale selection changed terminal state: %+v", after)
	}
}

func TestJobRetryRetainsFailedAttemptAndStartsNewExecution(t *testing.T) {
	run := JobRunRecord{Key: ResourceKey{Scope: Scope{"aws", "111111111111", "us-east-1"}, Name: "retry"}, ID: "jr_retry", State: "RUNNING", Version: 2, LaunchAttempted: true, MaxRetries: 1, Arguments: map[string]string{}}
	native := &jobTestRuntime{status: runtime.Status{Found: true, ExitCode: 1, ErrorOutput: "first attempt failed"}}
	s, source := executionFixture(t, run, native)
	executeOne(t, source)
	for range 4 {
		executeOne(t, source)
	}
	got := readTestRun(t, s, run)
	if got.Attempt != 1 || got.LaunchAttempted || got.ExecutionKey() == run.ExecutionKey() || len(got.Attempts) != 1 || got.Attempts[0].ErrorOutput != "first attempt failed" {
		t.Fatalf("retry did not retain its old execution: %+v", got)
	}
	native.status = runtime.Status{Found: true, ExitCode: 0, Output: "second attempt produced output"}
	executeOne(t, source)
	executeOne(t, source)
	got = readTestRun(t, s, run)
	if got.State != "SUCCEEDED" || native.starts != 1 || len(got.Attempts) != 2 || got.Attempts[0].State != "FAILED" || got.Attempts[1].State != "SUCCEEDED" {
		t.Fatalf("incorrect retried outcome: %+v starts=%d", got, native.starts)
	}
}

func TestJobTimeoutWinsOverSuccessfulExitObservation(t *testing.T) {
	run := JobRunRecord{Key: ResourceKey{Scope: Scope{"aws", "111111111111", "us-east-1"}, Name: "timeout"}, ID: "jr_timeout", State: "RUNNING", Version: 2, LaunchAttempted: true, Timeout: 2, StartedAt: time.Date(2026, 9, 26, 11, 57, 0, 0, time.UTC)}
	native := &jobTestRuntime{status: runtime.Status{Found: true, Running: true, ExitCode: 0}}
	s, source := executionFixture(t, run, native)
	executeOne(t, source)
	got := readTestRun(t, s, run)
	if got.State != "TIMEOUT" || native.stops != 1 {
		t.Fatalf("deadline lost to stale success: %+v stops=%d", got, native.stops)
	}
}
