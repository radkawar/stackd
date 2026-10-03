package cloudwatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type alarmEvaluationJobs struct{ service *Service }
type alarmActionJobs struct{ service *Service }

func (j alarmEvaluationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := j.service.repository.View(ctx, func(r Reader) error { var err error; job, found, err = r.NextAlarmEvaluation(); return err })
	return job, found, err
}

func (j alarmEvaluationJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.service
	return s.repository.Update(ctx, func(tx Transaction) error {
		alarm, err := tx.AlarmByID(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		now := s.clock.Now().UTC().Truncate(time.Millisecond)
		due, scheduled := alarm.EvaluationDeadline()
		if !scheduled || alarm.Version != job.Version || due.After(now) {
			return nil
		}
		if alarm.NextEvaluation != nil && !alarm.NextEvaluation.After(now) {
			if alarm.Composite != nil {
				if w := s.evaluateCompositeAlarms(tx, alarm, now); w != nil {
					return w
				}
				return nil
			}
			if w := s.evaluateMetricAlarm(tx, alarm, now); w != nil {
				return w
			}
			return nil
		}
		if alarm.SuppressionUntil != nil && !alarm.SuppressionUntil.After(now) {
			if w := s.advanceAlarmSuppression(tx, alarm, *alarm.SuppressionUntil, alarm.State.Origin); w != nil {
				return w
			}
		}
		return nil
	})
}

func (j alarmActionJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	var found bool
	err := j.service.repository.View(ctx, func(r Reader) error { var err error; job, found, err = r.NextAlarmAction(); return err })
	return job, found, err
}

func (j alarmActionJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.service
	var selected AlarmActionRecord
	eligible := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.AlarmAction(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != job.Version || current.Due.After(s.clock.Now()) {
			return nil
		}
		current.Version++
		if err := tx.PutAlarmAction(current); err != nil {
			return err
		}
		selected, eligible = current, true
		return nil
	})
	if err != nil || !eligible {
		return err
	}
	if s.actions == nil {
		return fmt.Errorf("CloudWatch alarm action sender is not configured")
	}
	metadata := awsctx.Metadata{Partition: selected.Key.Partition, AccountID: selected.Key.AccountID, Region: selected.Key.Region, RequestID: selected.RequestID, ParentEventID: selected.EventID}
	result := s.actions.Send(awsctx.WithMetadata(ctx, metadata), selected)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.AlarmAction(selected.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != selected.Version {
			return nil
		}
		if result == nil {
			if w := s.recordAlarmAction(tx, current, "Succeeded", ""); w != nil {
				return w
			}
			return tx.DeleteAlarmAction(current.ID)
		}
		// CloudWatch retries until Lambda accepts, except for missing functions and
		// permission failures. Once accepted, Lambda owns execution/retry policy.
		terminal := result.StatusCode == 403 || result.StatusCode == 404 || result.Code == "AccessDeniedException" || result.Code == "ResourceNotFoundException"
		if strings.SplitN(current.TargetARN, ":", 4)[2] == "autoscaling" && (result.StatusCode >= 400 && result.StatusCode < 500 || result.Code == "NotImplementedException") {
			terminal = true
		}
		if w := s.recordAlarmAction(tx, current, "Failed", result.Message); w != nil {
			return w
		}
		if terminal {
			return tx.DeleteAlarmAction(current.ID)
		}
		current.Attempts++
		delay := time.Second * time.Duration(1<<min(current.Attempts, 8))
		current.Due, current.Version = s.clock.Now().Add(delay), current.Version+1
		return tx.PutAlarmAction(current)
	})
}
