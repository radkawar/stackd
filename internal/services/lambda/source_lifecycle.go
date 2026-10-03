package lambda

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	"stackd/internal/scheduler"
)

// AWS documents periodic reoptimization, but no exact cadence. One hour is this
// implementation's local deterministic interval, not a native timing guarantee.
const codeSourceCheckInterval = time.Hour

type CodeSourceReader interface {
	// NextCodeSourceCheck orders active, nonpending own-code references by due
	// time then qualified ARN, including retained published versions.
	NextCodeSourceCheck() (scheduler.Job, bool, error)
}

type CodeSourceWriter interface {
	// SetCodeSourceState updates only source due time and operational state for
	// the exact nonpending version; published deployment content stays immutable.
	SetCodeSourceState(FunctionRecord) error
}

func (s *Service) scheduleCodeSourceCheck(v *FunctionRecord) {
	v.CodeSourceCheckAt = time.Time{}
	if v.Reference != nil {
		v.CodeSourceCheckAt = s.clock.Now().Add(codeSourceCheckInterval)
	}
}

func sameCodeSourceDeployment(a, b FunctionRecord) bool {
	if a.Key != b.Key || a.Version != b.Version || a.DeploymentRevision != b.DeploymentRevision {
		return false
	}
	if a.Reference == nil || b.Reference == nil {
		return a.Reference == nil && b.Reference == nil
	}
	return *a.Reference == *b.Reference
}

func codeSourceCheckEligible(v FunctionRecord) bool {
	return v.Reference != nil && v.State == "Active" && v.UpdateStatus != "InProgress"
}

type codeSourceJobs struct{ s *Service }

func (j codeSourceJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	s := j.s
	enabled := s.started.Load() && !s.closed.Load() && s.codeSource != nil
	if !enabled {
		return scheduler.Job{}, false, nil
	}
	var job scheduler.Job
	var found bool
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		job, found, err = r.NextCodeSourceCheck()
		return err
	})
	return job, found, err
}

func (j codeSourceJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil {
		return err
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(parsed.Resource, "function:"), ":")
	key := FunctionVersionKey{FunctionKey: FunctionKey{Scope: Scope{Partition: parsed.Partition, Account: parsed.AccountID, Region: parsed.Region}, Name: name}, Version: job.Version}
	var selected FunctionRecord
	var eligible bool
	err = j.s.repository.View(ctx, func(r Reader) error {
		var err error
		selected, err = r.FunctionVersion(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		eligible = codeSourceCheckEligible(selected) && selected.CodeSourceCheckAt.Equal(job.Due) && !job.Due.After(j.s.clock.Now())
		return nil
	})
	if err != nil || !eligible {
		return err
	}
	// The S3 owner performs real version and service-principal policy reads,
	// outside Lambda's transaction. Retained cache is not source authority.
	_, sourceError := j.s.codeSource.ReadReference(ctx, selected.Key.Scope, selected.Key.ARN(), *selected.Reference)
	if err := ctx.Err(); err != nil {
		return err
	}
	if sourceError != nil && sourceError.StatusCode >= 500 {
		// Leave the persisted deadline due; the existing scheduler retries errors.
		return sourceError
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.FunctionVersion(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !codeSourceCheckEligible(current) || !sameCodeSourceDeployment(selected, current) || !current.CodeSourceCheckAt.Equal(selected.CodeSourceCheckAt) {
			return nil
		}
		if sourceError == nil {
			current.CodeSourceCheckAt = j.s.clock.Now().Add(codeSourceCheckInterval)
		} else {
			// TODO: Comeback capture the native source-loss reason code; AWS documents Inactive but not its exact reason.
			current.State, current.StateReason, current.StateReasonCode = "Inactive", sourceError.Message, "DependencyError"
			current.Revision = uuid.NewString()
		}
		// Do not retire execution slots: already admitted customer work finishes.
		return tx.SetCodeSourceState(current)
	})
}
