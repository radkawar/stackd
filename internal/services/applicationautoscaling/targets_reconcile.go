package applicationautoscaling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type targetJobs struct{ s *Service }

func (j targetJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(reader Reader) error {
		key, due, exists, err := reader.NextTargetReconcile()
		if err != nil || !exists {
			return err
		}
		encoded, err := json.Marshal(key)
		if err != nil {
			return err
		}
		job, found = scheduler.Job{Key: string(encoded), Due: due}, true
		return nil
	})
	return
}

func (j targetJobs) Run(ctx context.Context, job scheduler.Job) error {
	var key TargetKey
	if err := json.Unmarshal([]byte(job.Key), &key); err != nil {
		return err
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		target, err := tx.Target(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if target.ReconcileAt.IsZero() || !target.ReconcileAt.Equal(job.Due) {
			return nil
		}
		return j.s.enforceBounds(jobContext(tx.Context(), key.Scope, target.OriginEventID), tx, &target)
	})
}

// enforceBounds commits accepted capacity intent with the target bounds.
// The resource owner alone observes and completes the actual change.
func (s *Service) enforceBounds(ctx context.Context, tx Transaction, target *TargetRecord) error {
	if s.identity == nil || s.resources == nil {
		return unsupported("Scaling requires the target service identity and resource provider")
	}
	service, err := s.identity.Context(ctx, target.Key, "AutoScaling-UpdateDesiredCapacity")
	if err != nil {
		return err
	}
	capacity, err := s.resources.Capacity(service, target.Key)
	if errors.Is(err, ErrNotFound) {
		return resourceMissing(service, s, tx, *target)
	}
	if err != nil {
		return err
	}
	desired := boundedCapacity(*target, float64(capacity.Desired))
	if desired != capacity.Desired {
		cause := fmt.Sprintf("maximum capacity was set to %d", desired)
		if desired > capacity.Desired {
			cause = fmt.Sprintf("minimum capacity was set to %d", desired)
		}
		if err := s.queueCapacity(service, tx, s.capacityActivity(target.Key, capacity.Running, desired, cause), nil); err != nil {
			return err
		}
	}
	target.ReconcileAt = time.Time{}
	return tx.PutTarget(*target)
}

func (s *Service) removeTarget(ctx context.Context, tx Transaction, target TargetRecord) error {
	policies, err := tx.Policies(PolicyQuery{Scope: target.Key.Scope, Namespace: target.Key.Namespace, ResourceID: target.Key.ResourceID, Dimension: target.Key.Dimension})
	if err != nil {
		return err
	}
	var alarms []string
	for _, policy := range policies {
		for _, alarm := range policy.Data.Alarms {
			alarms = append(alarms, value(alarm.AlarmName))
		}
	}
	if len(alarms) != 0 {
		if err := s.deleteManagedAlarms(ctx, target.Key, alarms); err != nil {
			return err
		}
	}
	return tx.DeleteTarget(target.Key)
}

// RemoveResource joins the resource owner's deletion transaction. Recreating an
// ECS service with the same name cannot resurrect its former scaling authority.
func (s *Service) RemoveResource(ctx context.Context, key TargetKey) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		target, err := tx.Target(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return s.removeTarget(tx.Context(), tx, target)
	})
}

// WithRoleUsage holds target mutations while IAM decides linked-role deletion.
func (s *Service) WithRoleUsage(ctx context.Context, partition, accountID string, fn func(context.Context, []TargetKey) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		keys, err := tx.TargetKeys(partition, accountID)
		if err != nil {
			return err
		}
		return fn(tx.Context(), keys)
	})
}

func jobContext(ctx context.Context, scope Scope, origin string) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, ParentEventID: origin, InvokedBy: "application-autoscaling.amazonaws.com", SourceIP: "application-autoscaling.amazonaws.com", UserAgent: "application-autoscaling.amazonaws.com"})
}
