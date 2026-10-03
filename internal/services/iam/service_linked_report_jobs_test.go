package iam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type heldLinkedUsage struct {
	entered chan context.Context
	release chan struct{}
	exited  chan error
	calls   atomic.Int32
}

func newHeldLinkedUsage() *heldLinkedUsage {
	return &heldLinkedUsage{entered: make(chan context.Context, 64), release: make(chan struct{}), exited: make(chan error, 64)}
}

func (u *heldLinkedUsage) WithServiceLinkedRoleUsage(ctx context.Context, _ ServiceLinkedRoleReference, fn func(context.Context, []ServiceLinkedRoleUsage) error) error {
	u.calls.Add(1)
	u.entered <- ctx
	defer func() { u.exited <- ctx.Err() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-u.release:
		return fn(ctx, nil)
	}
}

func awaitLinked[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		var zero T
		return zero
	}
}

type linkedReportRepository struct {
	Repository
	scope   Scope
	reports chan struct{}
}

func (r *linkedReportRepository) Update(ctx context.Context, fn func(WriteTx) error) error {
	complete := false
	err := r.Repository.Update(ctx, func(tx WriteTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		report, err := tx.CredentialReport(r.scope)
		complete = err == nil && report.State == CredentialReportComplete
		return nil
	})
	if err == nil && complete {
		select {
		case r.reports <- struct{}{}:
		default:
		}
	}
	return err
}

func TestServiceLinkedBlockedUsageDoesNotBlockCredentialReport(t *testing.T) {
	repository := &linkedReportRepository{Repository: NewMemoryRepository(nil), reports: make(chan struct{}, 1)}
	scope, _, job := seedLinkedJob(t, repository.Repository, serviceLinkedNotStarted)
	repository.scope = scope
	source := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
	s := NewWithConfig(Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	usage := newHeldLinkedUsage()
	if err := s.RegisterServiceLinkedRole(autoScalingLinkedTemplate(t, s), usage); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	drainContext, cancelDrain := context.WithCancel(ctx)
	result, err := s.RunDueJobs(drainContext, 1)
	if err != nil || result.Processed != 1 {
		t.Fatal("external check was not dispatched", result, err)
	}
	checkContext := awaitLinked(t, ctx, usage.entered)
	cancelDrain()
	if checkContext.Err() != nil {
		t.Fatal("the completed explicit drain canceled its external check")
	}
	for range 3 {
		result, err := s.RunDueJobs(ctx, 10)
		if err != nil || result.Processed != 0 || result.More {
			t.Fatal("in-flight task remained eligible", result, err)
		}
	}
	m := awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-east-1", PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), m)))
	}))
	t.Cleanup(server.Close)
	client := sdkiam.New(sdkiam.Options{Region: m.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1, HTTPClient: server.Client()})
	if _, err := client.GenerateCredentialReport(ctx, &sdkiam.GenerateCredentialReportInput{}); err != nil {
		t.Fatal(err)
	}
	awaitLinked(t, ctx, repository.reports)
	report, err := client.GetCredentialReport(ctx, &sdkiam.GetCredentialReportInput{})
	if err != nil || len(report.Content) == 0 || !aws.ToTime(report.GeneratedTime).Equal(source.Now()) {
		t.Fatal("blocked external check held up report generation", report, err)
	}
	if usage.calls.Load() != 1 || checkContext.Err() != nil {
		t.Fatal("report completion duplicated or canceled external work")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitLinked(t, ctx, usage.exited); !errors.Is(err, context.Canceled) {
		t.Fatal("Close did not cancel and join external work", err)
	}
	if got := readLinkedJob(t, repository, scope, job.ID); got.Status != serviceLinkedInProgress {
		t.Fatal("shutdown lost recoverable external work", got)
	}
	if source.Pending() != 0 {
		t.Fatal("Close left scheduler timers alive")
	}
}

type delayedLinkedFailureRepository struct {
	Repository
	fail    atomic.Bool
	failed  chan struct{}
	release chan struct{}
}

func (r *delayedLinkedFailureRepository) Update(ctx context.Context, fn func(WriteTx) error) error {
	if r.fail.CompareAndSwap(true, false) {
		close(r.failed)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.release:
			return errLinkedCommit
		}
	}
	return r.Repository.Update(ctx, fn)
}

func TestServiceLinkedAsyncRetryPublicationAfterTimerFires(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	repository := &delayedLinkedFailureRepository{Repository: NewMemoryRepository(nil), failed: make(chan struct{}), release: make(chan struct{})}
	scope, _, job := seedLinkedJob(t, repository.Repository, serviceLinkedNotStarted)
	epoch := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	source := clock.NewManual(epoch)
	s := NewWithConfig(Config{Repository: repository, Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	repository.fail.Store(true)
	s.StartWorkers()
	awaitLinked(t, ctx, repository.failed)
	if err := source.WaitForTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	// The first retry scan sees the still-running attempt. Await the next
	// recovery timer before allowing that attempt's failure bookkeeping.
	if err := source.WaitForTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	close(repository.release)
	waitPersistedLinkedStatus(t, repository, scope, job.ID, serviceLinkedSucceeded)
	if got := readLinkedJob(t, repository, scope, job.ID); !got.UpdatedAt.Equal(epoch.Add(time.Second)) {
		t.Fatal("failure publication postponed retry beyond its original deadline", got)
	}
}

func TestServiceLinkedAsyncRevalidatesRecreatedRole(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope, role, job := seedLinkedJob(t, repository, serviceLinkedNotStarted)
	s := NewWithConfig(Config{Repository: repository, Clock: clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))})
	t.Cleanup(func() { _ = s.Close() })
	usage := newHeldLinkedUsage()
	if err := s.RegisterServiceLinkedRole(autoScalingLinkedTemplate(t, s), usage); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if _, err := s.RunDueJobs(ctx, 1); err != nil {
		t.Fatal(err)
	}
	awaitLinked(t, ctx, usage.entered)
	role.RoleId = "AROARECREATEDWHILECHECKING"
	if err := repository.Update(ctx, func(tx WriteTx) error { return tx.PutRole(scope, role) }); err != nil {
		t.Fatal(err)
	}
	close(usage.release)
	waitPersistedLinkedStatus(t, repository, scope, job.ID, serviceLinkedFailed)
	if err := repository.View(ctx, func(tx ReadTx) error {
		current, err := tx.Role(scope, role.RoleName)
		if err == nil && current.RoleId != role.RoleId {
			t.Error("replacement role identity changed")
		}
		return err
	}); err != nil {
		t.Fatal("stale external completion removed a replacement role", err)
	}
}

func TestServiceLinkedCheckAdmissionBoundPreservesReportProgress(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope, role, job := seedLinkedJob(t, repository, serviceLinkedNotStarted)
	jobs := []string{job.ID}
	if err := repository.Update(t.Context(), func(tx WriteTx) error {
		for index := 1; index <= maxConcurrentServiceLinkedChecks; index++ {
			nextRole := role
			nextRole.RoleName += fmt.Sprintf("%02d", index)
			nextRole.RoleId += fmt.Sprintf("%02d", index)
			nextRole.Arn += fmt.Sprintf("%02d", index)
			nextJob := job
			nextJob.ID += fmt.Sprintf("%02d", index)
			nextJob.RoleID, nextJob.RoleName, nextJob.RoleARN = nextRole.RoleId, nextRole.RoleName, nextRole.Arn
			if err := tx.PutRole(scope, nextRole); err != nil {
				return err
			}
			if err := tx.PutServiceLinkedRoleDeletion(scope, nextJob); err != nil {
				return err
			}
			jobs = append(jobs, nextJob.ID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s := NewWithConfig(Config{Repository: repository, Clock: clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))})
	t.Cleanup(func() { _ = s.Close() })
	usage := newHeldLinkedUsage()
	if err := s.RegisterServiceLinkedRole(autoScalingLinkedTemplate(t, s), usage); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result, err := s.RunDueJobs(ctx, 100)
	if err != nil || result.Processed != maxConcurrentServiceLinkedChecks || result.More {
		t.Fatal("external check bound was not enforced", result, err)
	}
	for range maxConcurrentServiceLinkedChecks {
		awaitLinked(t, ctx, usage.entered)
	}
	if usage.calls.Load() != maxConcurrentServiceLinkedChecks {
		t.Fatal("too many external checks entered")
	}
	if err := repository.Update(ctx, func(tx WriteTx) error {
		if err := tx.PutAccountMetadata(scope, AccountMetadata{}); err != nil {
			return err
		}
		return tx.PutCredentialReport(scope, CredentialReportRecord{Generation: 1, State: CredentialReportPending})
	}); err != nil {
		t.Fatal(err)
	}
	result, err = s.RunDueJobs(ctx, 1)
	if err != nil || result.Processed != 1 {
		t.Fatal("saturated checks prevented another source's progress", result, err)
	}
	if err := repository.View(ctx, func(tx ReadTx) error {
		report, err := tx.CredentialReport(scope)
		if err == nil && report.State != CredentialReportComplete {
			t.Error("credential report did not complete while checks were saturated")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	close(usage.release)
	awaitLinked(t, ctx, usage.entered)
	for _, id := range jobs {
		waitPersistedLinkedStatus(t, repository, scope, id, serviceLinkedSucceeded)
	}
	if usage.calls.Load() != maxConcurrentServiceLinkedChecks+1 {
		t.Fatal("terminal completion did not admit the remaining persisted task")
	}
}

func TestServiceLinkedCloseRacesWithExternalCheckAdmission(t *testing.T) {
	repository := NewMemoryRepository(nil)
	scope, role, job := seedLinkedJob(t, repository, serviceLinkedNotStarted)
	s := NewWithConfig(Config{Repository: repository, Clock: clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))})
	t.Cleanup(func() { _ = s.Close() })
	usage := newHeldLinkedUsage()
	if err := s.RegisterServiceLinkedRole(autoScalingLinkedTemplate(t, s), usage); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if _, err := s.RunDueJobs(ctx, 1); err != nil {
		t.Fatal(err)
	}
	awaitLinked(t, ctx, usage.entered)
	role.RoleId += "-second"
	role.RoleName += "Second"
	role.Arn += "Second"
	job.ID += "-second"
	job.RoleID, job.RoleName, job.RoleARN = role.RoleId, role.RoleName, role.Arn
	if err := repository.Update(ctx, func(tx WriteTx) error {
		if err := tx.PutRole(scope, role); err != nil {
			return err
		}
		return tx.PutServiceLinkedRoleDeletion(scope, job)
	}); err != nil {
		t.Fatal(err)
	}
	start, done := make(chan struct{}), make(chan error, 20)
	for range 16 {
		go func() {
			<-start
			_, err := s.RunDueJobs(ctx, 1)
			if errors.Is(err, scheduler.ErrClosed) {
				err = nil
			}
			done <- err
		}()
	}
	for range 4 {
		go func() { <-start; done <- s.Close() }()
	}
	close(start)
	for range 20 {
		if err := awaitLinked(t, ctx, done); err != nil {
			t.Fatal(err)
		}
	}
	s.serviceLinked.mu.Lock()
	inflight := len(s.serviceLinked.inflight)
	s.serviceLinked.mu.Unlock()
	if inflight != 0 {
		t.Fatal("Close returned before all admitted external checks exited")
	}
	if got := readLinkedJob(t, repository, scope, job.ID); !serviceLinkedPending(got.Status) {
		t.Fatal("shutdown lost the racing task's recoverable state", got)
	}
}
