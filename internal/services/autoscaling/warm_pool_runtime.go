package autoscaling

import (
	"context"
	"errors"
	"strings"
	"time"
)

func launchActivity(kind string) bool {
	return kind == "launch" || kind == "warm-launch" || kind == "warm-start"
}

func terminateActivity(kind string) bool {
	return kind == "terminate" || kind == "warm-terminate" || kind == "warm-return"
}

func warmReady(member InstanceRecord) bool {
	switch value(member.Data.LifecycleState) {
	case "Warmed:Stopped", "Warmed:Running", "Warmed:Hibernated":
		return true
	default:
		return false
	}
}

func (s *Service) returnToWarmPool(tx Transaction, group GroupRecord, member InstanceRecord) error {
	if err := s.finishMemberActivity(tx.Context(), tx, group, member, nil); err != nil {
		return err
	}
	activity := s.newActivity(group, "warm-return", group.ReconcileCause)
	activity.InstanceID = value(member.Data.InstanceId)
	activity.WarmPoolState = value(group.Data.WarmPoolConfiguration.PoolState)
	text(&activity.Data.Description, "Returning EC2 instance to the warm pool: "+activity.InstanceID)
	member.ActivityID = activity.Key.ID
	member.InServiceAt, member.WarmUntil = time.Time{}, time.Time{}
	member.HealthCheckGraceIgnored = false
	boolean(&member.Data.ProtectedFromScaleIn, false)
	text(&member.Data.LifecycleState, "Warmed:Pending")
	if err := tx.PutActivity(activity); err != nil {
		return err
	}
	return tx.PutInstance(member)
}

func (s *Service) activateWarmMember(tx Transaction, group GroupRecord, member InstanceRecord) error {
	activity := s.newActivity(group, "warm-start", group.ReconcileCause)
	activity.InstanceID = value(member.Data.InstanceId)
	activity.InstanceWarmup = group.PendingInstanceWarmup
	activity.ProtectedFromScaleIn = group.Data.NewInstancesProtectedFromScaleIn != nil && bool(*group.Data.NewInstancesProtectedFromScaleIn)
	text(&activity.Data.Description, "Moving EC2 instance from the warm pool into the Auto Scaling group: "+activity.InstanceID)
	member.ActivityID = activity.Key.ID
	member.HealthCheckGraceIgnored = false
	text(&member.Data.LifecycleState, "Pending")
	if err := tx.PutActivity(activity); err != nil {
		return err
	}
	return tx.PutInstance(member)
}

func (s *Service) memberActivity(ctx context.Context, member InstanceRecord) (ActivityRecord, error) {
	var activity ActivityRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		activity, err = tx.Activity(ActivityKey{Scope: member.Group.Scope, ID: member.ActivityID})
		return err
	})
	return activity, err
}

func (s *Service) failWarmMember(ctx context.Context, group GroupRecord, member InstanceRecord, cause error) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
		if m.ActivityID != member.ActivityID || m.TerminationRequested {
			return false, nil
		}
		if err := s.finishMemberActivity(tx.Context(), tx, g, m, cause); err != nil {
			return false, err
		}
		text(&m.Data.HealthStatus, "Unhealthy")
		_, err := s.terminateMember(tx, g, &m, "Warm pool lifecycle failed: "+cause.Error())
		return true, err
	})
}

func (s *Service) reconcileWarmInstance(ctx context.Context, group GroupRecord, member InstanceRecord, observation InstanceObservation, ec2State string) (bool, error) {
	state := value(member.Data.LifecycleState)
	if state == "Warmed:Pending:Wait" {
		return false, nil
	}
	if state == "Warmed:Pending" {
		activity, err := s.memberActivity(ctx, member)
		if err != nil {
			return false, err
		}
		transition := launchTransition
		if activity.Kind == "warm-return" {
			drained, err := s.drainTargets(ctx, group, member)
			if err != nil || !drained {
				return false, err
			}
			transition = terminateTransition
		}
		if ec2State != "running" {
			if ec2State == "stopped" || ec2State == "shutting-down" {
				return s.failWarmMember(ctx, group, member, errors.New("EC2 instance stopped before warm pool initialization completed"))
			}
			return false, nil
		}
		return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			if m.TerminationRequested || value(m.Data.LifecycleState) != "Warmed:Pending" {
				return false, nil
			}
			waiting, err := s.beginLifecycleHooks(tx.Context(), tx, g, value(m.Data.InstanceId), transition)
			if err != nil {
				return false, err
			}
			if waiting {
				text(&activity.Data.StatusCode, "MidLifecycleAction")
				number(&activity.Data.Progress, 40)
				if err := tx.PutActivity(activity); err != nil {
					return false, err
				}
			}
			return true, nil
		})
	}
	if state == "Warmed:Pending:Proceed" {
		pool := group.Data.WarmPoolConfiguration
		if pool == nil || warmPoolDeleting(group) {
			return s.markUnhealthy(ctx, group, member, "Warm pool is being deleted.")
		}
		activity, err := s.memberActivity(ctx, member)
		if err != nil {
			return false, err
		}
		target := activity.WarmPoolState
		if target == "Hibernated" && (observation.Instance.HibernationOptions == nil || observation.Instance.HibernationOptions.Configured == nil || !bool(*observation.Instance.HibernationOptions.Configured)) {
			if activity.Kind != "warm-return" {
				return s.failWarmMember(ctx, group, member, errors.New("EC2 instance was not configured for hibernation"))
			}
			// AWS permits old, non-hibernation-enabled active members to be reused
			// as stopped instances. A failed hibernated restore never takes this path.
			target = "Stopped"
		}
		if target != "Running" && ec2State == "running" {
			if activity.RetryAt.After(s.clock.Now()) {
				return false, nil
			}
			if err := s.instances.Stop(ctx, value(member.Data.InstanceId), target == "Hibernated"); err != nil {
				if errors.Is(err, ErrInstanceHibernationNotReady) {
					return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
						if m.TerminationRequested || m.ActivityID != activity.Key.ID || value(m.Data.LifecycleState) != state {
							return false, nil
						}
						activity.RetryAt = s.clock.Now().Add(time.Minute)
						return true, tx.PutActivity(activity)
					})
				}
				return s.failWarmMember(ctx, group, member, err)
			}
			return false, nil
		}
		if ec2State == "shutting-down" || target == "Running" && (ec2State == "stopped" || ec2State == "stopping") {
			return s.failWarmMember(ctx, group, member, errors.New("EC2 instance stopped before entering the warm pool"))
		}
		if target == "Running" && ec2State != "running" || target != "Running" && ec2State != "stopped" {
			return false, nil
		}
		if target == "Hibernated" && (observation.Instance.StateReason == nil || value(observation.Instance.StateReason.Code) != "Client.UserInitiatedHibernate") {
			return s.failWarmMember(ctx, group, member, errors.New("EC2 instance stopped without an admitted hibernation request"))
		}
		return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			if m.TerminationRequested || value(m.Data.LifecycleState) != state {
				return false, nil
			}
			text(&m.Data.LifecycleState, "Warmed:"+target)
			if err := tx.PutInstance(m); err != nil {
				return false, err
			}
			return true, s.finishMemberActivity(tx.Context(), tx, g, m, nil)
		})
	}
	if !warmReady(member) {
		return false, nil
	}
	healthy := observation.Healthy
	if state == "Warmed:Running" {
		healthy = healthy && ec2State == "running"
	} else {
		healthy = healthy && ec2State == "stopped"
	}
	if value(member.Data.HealthStatus) == "Unhealthy" || !processSuspended(group, "HealthCheck") && !healthy {
		return s.markUnhealthy(ctx, group, member, "Warm pool instance failed EC2 or EBS health checks.")
	}
	return false, nil
}

func lifecycleEndpoints(kind, state string) (string, string) {
	switch kind {
	case "warm-launch":
		return "EC2", "WarmPool"
	case "warm-start":
		return "WarmPool", "AutoScalingGroup"
	case "warm-return":
		return "AutoScalingGroup", "WarmPool"
	case "warm-terminate":
		return "WarmPool", "EC2"
	case "launch":
		return "EC2", "AutoScalingGroup"
	default:
		if strings.HasPrefix(state, "Warmed:") {
			return "WarmPool", "EC2"
		}
		return "AutoScalingGroup", "EC2"
	}
}
