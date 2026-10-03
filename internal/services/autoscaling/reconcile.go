package autoscaling

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// The group/activity rows own recovery. The active map only prevents concurrent
// native calls for one group; guest execution never holds the shared drain gate.
type groupEffects struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	work   sync.WaitGroup
	active map[GroupKey]struct{}
	closed bool
}

func newGroupEffects() *groupEffects {
	ctx, cancel := context.WithCancel(context.Background())
	return &groupEffects{ctx: ctx, cancel: cancel, active: map[GroupKey]struct{}{}}
}
func (s *Service) Start() error { s.jobs.Start(); return nil }
func (s *Service) Close() error {
	s.effects.mu.Lock()
	s.effects.closed = true
	s.effects.cancel()
	s.effects.mu.Unlock()
	s.jobs.Close()
	s.effects.work.Wait()
	return nil
}

type groupJobs struct{ s *Service }

func (j groupJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(tx Reader) error {
		groups, err := tx.PendingGroups()
		if err != nil {
			return err
		}
		j.s.effects.mu.Lock()
		defer j.s.effects.mu.Unlock()
		if j.s.effects.closed {
			return nil
		}
		for _, group := range groups {
			due := group.Due
			if _, active := j.s.effects.active[group.Key]; active {
				due = time.Time{}
			}
			// Native work owns only reconciliation. A due metric window must
			// still drain while that group's external effect is in flight.
			if !group.Deleting && !group.MetricAt.IsZero() && (due.IsZero() || group.MetricAt.Before(due)) {
				due = group.MetricAt
			}
			if due.IsZero() {
				continue
			}
			candidate := scheduler.Job{Key: group.Key.ARN(group.ID), Version: group.Version, Due: due}
			if !found || scheduler.Compare(candidate, next) < 0 {
				next = candidate
				found = true
			}
		}
		return nil
	})
	return next, found, err
}

func parseGroupARN(arn string) (GroupKey, string, error) {
	parts := strings.SplitN(arn, ":", 8)
	if len(parts) != 8 || parts[0] != "arn" || parts[2] != "autoscaling" || parts[5] != "autoScalingGroup" || !strings.HasPrefix(parts[7], "autoScalingGroupName/") {
		return GroupKey{}, "", invalid("The Auto Scaling group ARN is not valid.")
	}
	return GroupKey{Scope: Scope{Partition: parts[1], AccountID: parts[4], Region: parts[3]}, Name: strings.TrimPrefix(parts[7], "autoScalingGroupName/")}, parts[6], nil
}

func (j groupJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	key, id, err := parseGroupARN(job.Key)
	if err != nil {
		return err
	}
	var group GroupRecord
	err = s.repository.View(ctx, func(tx Reader) error { var err error; group, err = tx.Group(key); return err })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if group.ID != id || group.Version != job.Version || (!group.ReconcileAt.Equal(job.Due) && !group.MetricAt.Equal(job.Due)) || job.Due.After(s.clock.Now()) {
		return nil
	}
	metadata := awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, ParentEventID: group.OriginEventID, InvokedBy: ServicePrincipal, SourceIP: ServicePrincipal, UserAgent: ServicePrincipal, ServicePrincipal: awsctx.ServicePrincipal{Name: ServicePrincipal, SourceARN: key.ARN(id)}}
	// Publishing retained state is deterministic service work. Do not put it
	// behind a guest worker that may still be running when a clock drain returns.
	if err := s.publishGroupMetrics(awsctx.WithMetadata(ctx, metadata), group); err != nil {
		return err
	}
	if group.ReconcileAt.IsZero() || group.ReconcileAt.After(s.clock.Now()) {
		return nil
	}
	s.effects.mu.Lock()
	defer s.effects.mu.Unlock()
	if s.effects.closed {
		return nil
	}
	if _, active := s.effects.active[key]; active {
		return nil
	}
	s.effects.active[key] = struct{}{}
	s.effects.work.Go(func() {
		ctx := awsctx.WithMetadata(s.effects.ctx, metadata)
		immediate, err := s.runGroup(ctx, key, id)
		if ctx.Err() == nil {
			if err != nil {
				slog.ErrorContext(ctx, "Auto Scaling reconciliation failed", "group", key.ARN(id), "error", err)
			}
			if completionErr := s.finishGroupPass(ctx, key, id, job.Version, immediate, err); completionErr != nil {
				slog.ErrorContext(ctx, "Auto Scaling reconciliation state failed", "group", key.ARN(id), "error", completionErr)
			}
		}
		s.effects.mu.Lock()
		delete(s.effects.active, key)
		s.effects.mu.Unlock()
		s.jobs.Wake()
	})
	return nil
}

func (s *Service) finishGroupPass(ctx context.Context, key GroupKey, id string, version uint64, immediate bool, effectErr error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		group, err := tx.Group(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if group.ID != id {
			return nil
		}
		// An intervening API or lifecycle completion owns its earlier wakeup.
		if group.Version != version {
			return nil
		}
		delay := 5 * time.Second
		if effectErr != nil {
			delay = 30 * time.Second
		} else if immediate {
			delay = 0
		}
		group.Version++
		group.ReconcileAt = s.clock.Now().Add(delay)
		if effectErr == nil && !immediate && !group.Deleting && intValue(group.Data.DesiredCapacity) == 0 && warmPoolDesired(group) == 0 {
			members, err := tx.Instances(group.Key)
			if err != nil {
				return err
			}
			if len(members) == 0 {
				refreshes, err := tx.Refreshes(group.Key)
				if err != nil {
					return err
				}
				if _, active := activeRefresh(refreshes, group.ID); !active {
					group.ReconcileAt = group.MetricAt
				}
			}
		}
		return tx.PutGroup(group)
	})
}

func (s *Service) runGroup(ctx context.Context, key GroupKey, id string) (bool, error) {
	var group GroupRecord
	var members []InstanceRecord
	var activities []ActivityRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		group, err = tx.Group(key)
		if err != nil {
			return err
		}
		members, err = tx.Instances(key)
		if err != nil {
			return err
		}
		activities, err = tx.Activities(key.Scope, key.Name, false)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if group.ID != id {
		return false, nil
	}
	if s.identity == nil || s.instances == nil {
		return false, unsupported("EC2 Auto Scaling execution is not configured.")
	}
	execution, err := s.identity.Context(ctx, group)
	if err != nil {
		return false, err
	}
	for _, activity := range activities {
		if activity.Data.EndTime == nil && (activity.Kind == "launch" || activity.Kind == "warm-launch") && activity.InstanceID == "" {
			if activity.Kind == "warm-launch" && (group.Deleting || group.Data.WarmPoolConfiguration == nil || warmPoolDeleting(group)) {
				err := s.repository.Update(ctx, func(tx Transaction) error {
					current, err := tx.Group(group.Key)
					if err != nil {
						return err
					}
					if current.ID != group.ID {
						return nil
					}
					return s.cancelActivity(tx.Context(), tx, current, activity, "Warm pool deletion cancelled the pending launch.")
				})
				return err == nil, err
			}
			if activity.RetryAt.After(s.clock.Now()) {
				continue
			}
			return s.executeLaunch(execution, group, activity)
		}
	}
	if len(members) > 0 {
		ids := make([]string, len(members))
		for i, member := range members {
			ids[i] = value(member.Data.InstanceId)
		}
		observations, err := s.instances.Observe(execution, ids)
		if err != nil {
			return false, err
		}
		byID := make(map[string]InstanceObservation, len(observations))
		for _, observation := range observations {
			byID[value(observation.Instance.InstanceId)] = observation
		}
		for _, member := range members {
			observation, exists := byID[value(member.Data.InstanceId)]
			changed, err := s.reconcileInstance(execution, group, member, observation, exists)
			if err != nil {
				return false, err
			}
			if changed {
				return true, nil
			}
		}
	}
	if handled, changed, err := s.reconcileRefresh(execution, group); handled || err != nil {
		return changed, err
	}
	if changed, err := s.reconcileExpiredInstances(execution, group, members); changed || err != nil {
		return changed, err
	}
	return s.reconcileCapacity(execution, group)
}
