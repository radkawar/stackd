package applicationautoscaling

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/internal/awsschedule"
	"stackd/internal/scheduler"
)

// scheduleJobs keeps the deadline with the target change. A permanent rejected
// attempt consumes this occurrence, without retaining partial resource changes
// or allowing one failed action to block unrelated service jobs.
type scheduleJobs struct{ s *Service }

func scheduleJobKey(key ScheduleKey) string {
	return strings.Join([]string{key.Partition, key.AccountID, key.Region, key.Namespace, key.ResourceID, key.Dimension, key.Name}, "\x00")
}

func (j scheduleJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var key ScheduleKey
	var due time.Time
	var found bool
	err := j.s.repository.View(ctx, func(reader Reader) error {
		var err error
		key, due, found, err = reader.NextSchedule()
		return err
	})
	if err != nil || !found {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: scheduleJobKey(key), Due: due}, true, nil
}

func (j scheduleJobs) Run(ctx context.Context, job scheduler.Job) error {
	var rejected error
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		key, due, found, err := tx.NextSchedule()
		if err != nil || !found {
			return err
		}
		now := j.s.clock.Now()
		if scheduleJobKey(key) != job.Key || !due.Equal(job.Due) || due.After(now) {
			return nil
		}
		record, err := tx.Schedule(key)
		if err != nil {
			return err
		}
		target, err := tx.Target(key.TargetKey)
		if errors.Is(err, ErrNotFound) {
			return tx.DeleteSchedule(key)
		}
		if err != nil {
			return err
		}
		suspended := target.Data.SuspendedState != nil && target.Data.SuspendedState.ScheduledScalingSuspended != nil && bool(*target.Data.SuspendedState.ScheduledScalingSuspended)
		if !suspended && (record.Data.EndTime == nil || !now.After(*record.Data.EndTime)) {
			rejected = j.s.repository.Attempt(tx.Context(), func(command Transaction) error {
				return j.s.applyScheduledAction(command, record, target)
			})
			if rejected != nil {
				status := wireError(rejected).StatusCode
				if status < 400 || status >= 500 {
					return rejected
				}
				activity := j.s.scheduledActivity(record)
				activity.Data.StatusCode = new(api.ScalingActivityStatusCodeFailed)
				activity.Data.StatusMessage = new(api.XmlString(wireError(rejected).Message))
				if err := j.s.insertActivity(tx, activity); err != nil {
					return err
				}
			}
		}
		if err := advanceScheduledDeadline(&record, now); err != nil {
			return err
		}
		return tx.PutSchedule(record)
	})
	if err != nil {
		return err
	}
	// Report the failed occurrence through the existing scheduler error/log
	// boundary only after its consumed deadline has committed.
	return rejected
}

func (s *Service) applyScheduledAction(tx Transaction, record ScheduleRecord, target TargetRecord) error {
	action := record.Data.ScalableTargetAction
	if action.MinCapacity != nil {
		target.Data.MinCapacity = new(*action.MinCapacity)
	}
	if action.MaxCapacity != nil {
		target.Data.MaxCapacity = new(*action.MaxCapacity)
	}
	if *target.Data.MinCapacity > *target.Data.MaxCapacity {
		return invalid("Scheduled action minimum capacity cannot exceed the target maximum capacity")
	}
	if err := s.insertActivity(tx, s.scheduledActivity(record)); err != nil {
		return err
	}
	return s.enforceBounds(jobContext(tx.Context(), record.Key.Scope, record.OriginEventID), tx, &target)
}

func (s *Service) scheduledActivity(record ScheduleRecord) ActivityRecord {
	var changes []string
	if min := record.Data.ScalableTargetAction.MinCapacity; min != nil {
		changes = append(changes, fmt.Sprintf("min capacity to %d", *min))
	}
	if max := record.Data.ScalableTargetAction.MaxCapacity; max != nil {
		changes = append(changes, fmt.Sprintf("max capacity to %d", *max))
	}
	description := strings.Join(changes, " and ")
	activity := s.newActivity(record.Key.TargetKey, "Setting "+description, "scheduled action name "+record.Key.Name+" was triggered", api.ScalingActivityStatusCodeSuccessful)
	activity.Data.EndTime = new(*activity.Data.StartTime)
	activity.Data.StatusMessage = new(api.XmlString("Successfully set " + description))
	return activity
}

func advanceScheduledDeadline(record *ScheduleRecord, now time.Time) error {
	parsed, err := awsschedule.ParseApplicationAutoScaling(value(record.Data.Schedule), value(record.Data.Timezone))
	if err != nil {
		return err
	}
	// Coalesce missed recurrences rather than executing a loop for every
	// minute in a large clock advance. A rate remains anchored to its due time.
	next, exists := parsed.NextAfter(record.NextDue, now)
	if !exists || record.Data.EndTime != nil && next.After(*record.Data.EndTime) {
		record.NextDue = time.Time{}
	} else {
		record.NextDue = next
	}
	return nil
}

// skipSuspendedSchedules fences a resume against overdue work which has not yet
// been drained. The caller invokes this while the old suspension is still true.
func (s *Service) skipSuspendedSchedules(tx Transaction, key TargetKey, now time.Time) error {
	rows, err := tx.Schedules(ScheduleQuery{Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension})
	if err != nil {
		return err
	}
	for _, record := range rows {
		if record.NextDue.IsZero() || record.NextDue.After(now) {
			continue
		}
		if err := advanceScheduledDeadline(&record, now); err != nil {
			return err
		}
		if err := tx.PutSchedule(record); err != nil {
			return err
		}
	}
	return nil
}
