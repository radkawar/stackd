package applicationautoscaling

import (
	"context"
	"errors"
	"fmt"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

func (s *Service) capacityActivity(key TargetKey, from, to int32, cause string) ActivityRecord {
	record := s.newActivity(key, fmt.Sprintf("Setting %s to %d.", capacityName(key), to), cause, api.ScalingActivityStatusCodePending)
	record.From, record.To = from, to
	return record
}

func (s *Service) queueCapacity(ctx context.Context, tx Transaction, record ActivityRecord, policy *PolicyRecord) error {
	record.OriginEventID = apievents.EventID(ctx)
	if record.OriginEventID == "" {
		record.OriginEventID = awsctx.FromContext(ctx).ParentEventID
	}
	if policy != nil {
		record.PolicyName = policy.Key.Name
		policy.PendingActivityID = record.Key.ID
		if err := tx.PutPolicy(*policy); err != nil {
			return err
		}
	}
	return s.insertActivity(tx, record)
}

type activityJobs struct{ s *Service }

func activityJob(record ActivityRecord) scheduler.Job {
	return scheduler.Job{Key: fmt.Sprintf("%020d:%s", record.Sequence, record.Key.ID), Due: *record.Data.StartTime}
}

func (j activityJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var record ActivityRecord
	var found bool
	err := j.s.repository.View(ctx, func(reader Reader) error {
		var err error
		record, found, err = reader.NextPendingActivity()
		return err
	})
	if err != nil || !found {
		return scheduler.Job{}, false, err
	}
	return activityJob(record), true, nil
}

// Pending intent is independently recoverable after acceptance. The resource
// command and InProgress transition commit together; the resource's actual lifecycle
// completes it through ObserveCapacity rather than an optimistic API result.
func (j activityJobs) Run(ctx context.Context, job scheduler.Job) error {
	var rejected error
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		record, found, err := tx.NextPendingActivity()
		if err != nil || !found {
			return err
		}
		current := activityJob(record)
		if current.Key != job.Key || !current.Due.Equal(job.Due) || current.Due.After(j.s.clock.Now()) {
			return nil
		}
		rejected = j.s.repository.Attempt(tx.Context(), func(command Transaction) error {
			if j.s.identity == nil || j.s.resources == nil {
				return unsupported("Scaling requires the target service identity and resource provider")
			}
			key := activityTarget(record)
			service, err := j.s.identity.Context(jobContext(command.Context(), key.Scope, record.OriginEventID), key, "AutoScaling-UpdateDesiredCapacity")
			if err != nil {
				return err
			}
			record.Data.StatusCode = new(api.ScalingActivityStatusCodeInProgress)
			record.Data.StatusMessage = new(api.XmlString(fmt.Sprintf("Successfully set %s to %d. Waiting for change to be fulfilled by %s.", capacityName(key), record.To, key.Namespace)))
			if err := command.PutActivity(record); err != nil {
				return err
			}
			return j.s.resources.SetCapacity(service, key, record.To)
		})
		if rejected == nil {
			return nil
		}
		failure := wireError(rejected)
		if failure.StatusCode < 400 || failure.StatusCode >= 500 {
			return rejected
		}
		var dependency interface{ RecordRejection(context.Context) error }
		if errors.As(rejected, &dependency) {
			if err := dependency.RecordRejection(tx.Context()); err != nil {
				return err
			}
		}
		record.Data.StatusCode = new(api.ScalingActivityStatusCodeFailed)
		record.Data.EndTime = new(j.s.clock.Now().UTC().Truncate(time.Millisecond))
		record.Data.StatusMessage = new(api.XmlString(fmt.Sprintf("Failed to set %s to %d. Reason: %s", capacityName(activityTarget(record)), record.To, failure.Message)))
		return j.s.finishActivity(tx, record)
	})
	if err != nil {
		return err
	}
	// A terminal failure is consumed before the scheduler reports it. It cannot
	// block unrelated scaling work or replay a partially applied ECS mutation.
	return rejected
}
