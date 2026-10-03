package autoscaling

import (
	"context"
	"errors"
	"strings"
	"time"
)

func (s *Service) updateMembership(ctx context.Context, group GroupRecord, member InstanceRecord, change func(Transaction, GroupRecord, InstanceRecord) (bool, error)) (bool, error) {
	changed := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Group(group.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != group.ID {
			return nil
		}
		owned, err := tx.Instance(group.Key.Scope, value(member.Data.InstanceId))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if owned.Group != group.Key || owned.GroupID != group.ID {
			return nil
		}
		changed, err = change(tx, current, owned)
		return err
	})
	return changed, err
}

func (s *Service) reconcileInstance(ctx context.Context, group GroupRecord, member InstanceRecord, observation InstanceObservation, exists bool) (bool, error) {
	state := ""
	if observation.Instance.State != nil {
		state = value(observation.Instance.State.Name)
	}
	if !exists || state == "terminated" {
		return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			if !m.TerminationRequested {
				if _, err := s.terminateMember(tx, g, &m, "EC2 instance is no longer available."); err != nil {
					return false, err
				}
			}
			if err := s.finishMemberActivity(tx.Context(), tx, g, m, nil); err != nil {
				return false, err
			}
			if err := deleteInstanceActions(tx, g, value(m.Data.InstanceId)); err != nil {
				return false, err
			}
			return true, tx.DeleteInstance(g.Key.Scope, value(m.Data.InstanceId))
		})
	}
	if member.DetachRequested {
		return s.drainMembership(ctx, group, member, true)
	}
	lifecycle := value(member.Data.LifecycleState)
	if warmMember(member) && warmPoolDeleting(group) && (!member.TerminationRequested || retainedMember(member)) {
		return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			if !warmPoolDeleting(g) || !warmMember(m) || m.TerminationRequested && !retainedMember(m) {
				return false, nil
			}
			// Pending warm-pool deletion keeps requesting removal, including a
			// fresh hook after ABANDON retains a member. Ordinary retention stops
			// below; an existing terminating hook is never restarted here.
			m.TerminationRequested = false
			_, err := s.terminateMember(tx, g, &m, "Warm pool deletion requested.")
			return err == nil, err
		})
	}
	if retainedMember(member) {
		return false, nil
	}
	if member.TerminationRequested || group.Deleting {
		return s.reconcileTermination(ctx, group, member, state)
	}
	if warmMember(member) {
		return s.reconcileWarmInstance(ctx, group, member, observation, state)
	}
	if lifecycle == "Pending" && state == "stopped" {
		activity, err := s.memberActivity(ctx, member)
		if err != nil {
			return false, err
		}
		if activity.Kind == "warm-start" {
			if value(activity.Data.StatusCode) == "PreInService" {
				return s.failWarmMember(ctx, group, member, errors.New("EC2 instance stopped while starting from the warm pool"))
			}
			if err := s.instances.Start(ctx, value(member.Data.InstanceId)); err != nil {
				return s.failWarmMember(ctx, group, member, err)
			}
			return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
				if m.TerminationRequested || g.Deleting || m.ActivityID != activity.Key.ID || value(m.Data.LifecycleState) != "Pending" {
					return false, nil
				}
				text(&activity.Data.StatusCode, "PreInService")
				number(&activity.Data.Progress, 30)
				return true, tx.PutActivity(activity)
			})
		}
	}
	if lifecycle == "EnteringStandby" {
		return s.drainMembership(ctx, group, member, false)
	}
	if lifecycle == "Standby" {
		return false, nil
	}
	if state == "stopped" || state == "stopping" || state == "shutting-down" {
		if value(member.Data.HealthStatus) == "Unhealthy" || !processSuspended(group, "HealthCheck") {
			return s.markUnhealthy(ctx, group, member, "EC2 instance is "+state)
		}
	}
	if state != "running" {
		return false, nil
	}
	if lifecycle == "Pending:Wait" {
		return false, nil
	}
	if lifecycle == "Pending" {
		return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			if m.TerminationRequested || value(m.Data.LifecycleState) != "Pending" {
				return false, nil
			}
			activity, err := tx.Activity(ActivityKey{Scope: g.Key.Scope, ID: m.ActivityID})
			if err != nil {
				return false, err
			}
			waiting := false
			if launchActivity(activity.Kind) {
				waiting, err = s.beginLifecycleHooks(tx.Context(), tx, g, value(m.Data.InstanceId), launchTransition)
				if err != nil {
					return false, err
				}
			} else {
				text(&m.Data.LifecycleState, "Pending:Proceed")
				if err := tx.PutInstance(m); err != nil {
					return false, err
				}
			}
			if waiting {
				text(&activity.Data.StatusCode, "MidLifecycleAction")
				number(&activity.Data.Progress, 40)
			} else {
				text(&activity.Data.StatusCode, "PreInService")
				number(&activity.Data.Progress, 30)
			}
			return true, tx.PutActivity(activity)
		})
	}
	if lifecycle == "Pending:Proceed" {
		// Registration belongs to admission, not steady-state reconciliation:
		// resuming AddToLoadBalancer must not backfill existing members.
		if !processSuspended(group, "AddToLoadBalancer") {
			for _, target := range group.Data.TargetGroupARNs {
				if err := s.targetGroups.Register(ctx, group.Key.ARN(group.ID), string(target), value(member.Data.InstanceId)); err != nil {
					return false, err
				}
			}
		}
		return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			if m.TerminationRequested || value(m.Data.LifecycleState) != "Pending:Proceed" {
				return false, nil
			}
			activity, err := tx.Activity(ActivityKey{Scope: g.Key.Scope, ID: m.ActivityID})
			if err != nil {
				return false, err
			}
			m.InServiceAt = s.clock.Now()
			warmup := intValue(g.Data.DefaultInstanceWarmup)
			if activity.InstanceWarmup != nil {
				warmup = int64(*activity.InstanceWarmup)
			}
			if warmup > 0 {
				m.WarmUntil = m.InServiceAt.Add(time.Duration(warmup) * time.Second)
			}
			if launchActivity(activity.Kind) {
				boolean(&m.Data.ProtectedFromScaleIn, activity.ProtectedFromScaleIn)
			}
			text(&m.Data.LifecycleState, "InService")
			if err := tx.PutInstance(m); err != nil {
				return false, err
			}
			if m.WarmUntil.After(s.clock.Now()) {
				text(&activity.Data.StatusCode, "WaitingForInstanceWarmup")
				number(&activity.Data.Progress, 50)
				return true, tx.PutActivity(activity)
			}
			return true, s.finishMemberActivity(tx.Context(), tx, g, m, nil)
		})
	}
	if lifecycle != "InService" {
		return false, nil
	}
	if member.ActivityID != "" && !member.WarmUntil.After(s.clock.Now()) {
		changed, err := s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			activity, err := tx.Activity(ActivityKey{Scope: g.Key.Scope, ID: m.ActivityID})
			if err != nil {
				return false, err
			}
			if activity.Data.EndTime != nil {
				return false, nil
			}
			return true, s.finishMemberActivity(tx.Context(), tx, g, m, nil)
		})
		if err != nil || changed {
			return changed, err
		}
	}
	grace := member.InServiceAt.Add(time.Duration(intValue(group.Data.HealthCheckGracePeriod)) * time.Second)
	if !member.HealthCheckGraceIgnored && grace.After(s.clock.Now()) {
		return false, nil
	}
	// TODO: Comeback calibrate sustained EC2 status-check impairment before
	// replacement; native ASG tolerates intermittent failure for a few minutes.
	healthy := observation.Healthy
	if !processSuspended(group, "HealthCheck") && value(group.Data.HealthCheckType) == "ELB" {
		for _, target := range group.Data.TargetGroupARNs {
			ready, err := s.targetGroups.Healthy(ctx, group.Key.ARN(group.ID), string(target), value(member.Data.InstanceId))
			if err != nil {
				return false, err
			}
			healthy = healthy && ready
		}
	}
	if value(member.Data.HealthStatus) == "Unhealthy" || !processSuspended(group, "HealthCheck") && !healthy {
		return s.markUnhealthy(ctx, group, member, "EC2 instance failed the configured health checks.")
	}
	return false, nil
}

func (s *Service) reconcileExpiredInstances(ctx context.Context, group GroupRecord, members []InstanceRecord) (bool, error) {
	lifetime := intValue(group.Data.MaxInstanceLifetime)
	if group.Deleting || lifetime == 0 || processSuspended(group, "Launch") || processSuspended(group, "Terminate") {
		return false, nil
	}
	now := s.clock.Now()
	ready := int64(0)
	var eligible []string
	for _, member := range members {
		if !countsCapacity(member) {
			continue
		}
		// Keep ordinary lifetime replacement one-at-a-time, including while
		// the previous retirement is waiting on hooks or target draining.
		if member.TerminationRequested {
			return false, nil
		}
		if value(member.Data.LifecycleState) != "InService" || value(member.Data.HealthStatus) != "Healthy" || member.WarmUntil.After(now) {
			continue
		}
		ready++
		if !member.JoinedAt.Add(time.Duration(lifetime) * time.Second).After(now) {
			eligible = append(eligible, value(member.Data.InstanceId))
		}
	}
	// Let capacity reconciliation restore the previous replacement before
	// retiring another serving member.
	// TODO: Comeback calibrate AWS's accelerated lifetime replacement (up to
	// ten percent of capacity) when one-at-a-time renewal cannot keep up.
	if ready < intValue(group.Data.DesiredCapacity) || len(eligible) == 0 {
		return false, nil
	}
	selected, err := s.selectTerminations(ctx, group, members, "MAX_INSTANCE_LIFETIME", 1, eligible)
	if err != nil || len(selected) == 0 {
		return false, err
	}
	changed := false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := terminationSelectionCurrent(tx, group, members)
		if err != nil || !current {
			return err
		}
		for _, member := range selected {
			if _, err := s.terminateMember(tx, group, &member, "EC2 instance reached its maximum instance lifetime."); err != nil {
				return err
			}
		}
		changed = true
		return nil
	})
	return changed, err
}

func (s *Service) markUnhealthy(ctx context.Context, group GroupRecord, member InstanceRecord, cause string) (bool, error) {
	return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
		changed := value(m.Data.HealthStatus) != "Unhealthy"
		text(&m.Data.HealthStatus, "Unhealthy")
		// Terminate suspension protects InService instances from new automatic
		// termination, not failed Pending instances or already-admitted work.
		terminateSuspended := (value(m.Data.LifecycleState) == "InService" || warmReady(m)) && processSuspended(g, "Terminate")
		if !processSuspended(g, "ReplaceUnhealthy") && !terminateSuspended && !m.TerminationRequested {
			if _, err := s.terminateMember(tx, g, &m, cause); err != nil {
				return false, err
			}
			return true, nil
		}
		if !changed {
			return false, nil
		}
		return true, tx.PutInstance(m)
	})
}

func deleteInstanceActions(tx Transaction, group GroupRecord, id string) error {
	actions, err := tx.LifecycleActions(group.Key)
	if err != nil {
		return err
	}
	for _, action := range actions {
		if action.InstanceID == id {
			if err := tx.DeleteLifecycleAction(group.Key, action.Token); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) reconcileTermination(ctx context.Context, group GroupRecord, member InstanceRecord, ec2State string) (bool, error) {
	lifecycle := value(member.Data.LifecycleState)
	prefix := ""
	if warmMember(member) {
		prefix = "Warmed:"
	}
	if !strings.HasPrefix(lifecycle, prefix+"Terminating") {
		return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			activity, err := tx.Activity(ActivityKey{Scope: g.Key.Scope, ID: m.ActivityID})
			if err != nil {
				return false, err
			}
			if activity.Kind != "terminate" && activity.Kind != "warm-terminate" {
				if activity.Data.EndTime == nil {
					if err := s.cancelActivity(tx.Context(), tx, g, activity, "Lifecycle action was abandoned."); err != nil {
						return false, err
					}
				}
				cause := "Removing instance from the Auto Scaling group."
				if g.Deleting {
					cause = "Auto Scaling group deletion requested."
				}
				kind := "terminate"
				if warmMember(m) {
					kind = "warm-terminate"
				}
				activity = s.newActivity(g, kind, cause)
				activity.InstanceID = value(m.Data.InstanceId)
				text(&activity.Data.Description, "Terminating EC2 instance: "+activity.InstanceID)
				m.ActivityID = activity.Key.ID
			}
			m.TerminationRequested = true
			text(&m.Data.LifecycleState, prefix+"Terminating")
			if err := tx.PutActivity(activity); err != nil {
				return false, err
			}
			if err := tx.PutInstance(m); err != nil {
				return false, err
			}
			return true, nil
		})
	}
	if lifecycle == prefix+"Terminating" {
		// Deregistration and connection draining precede the termination hook.
		// A retained instance then stays out of target traffic without repeating
		// native deregistration on every reconciliation.
		drained, err := s.drainTargets(ctx, group, member)
		if err != nil || !drained {
			return false, err
		}
		return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
			if value(m.Data.LifecycleState) != prefix+"Terminating" {
				return false, nil
			}
			waiting, err := s.beginLifecycleHooks(tx.Context(), tx, g, value(m.Data.InstanceId), terminateTransition)
			if err != nil {
				return false, err
			}
			if waiting {
				activity, err := tx.Activity(ActivityKey{Scope: g.Key.Scope, ID: m.ActivityID})
				if err != nil {
					return false, err
				}
				text(&activity.Data.StatusCode, "MidTerminatingLifecycleAction")
				number(&activity.Data.Progress, 60)
				if err := tx.PutActivity(activity); err != nil {
					return false, err
				}
			}
			return true, nil
		})
	}
	if lifecycle == prefix+"Terminating:Wait" {
		return false, nil
	}
	if ec2State == "shutting-down" {
		return false, nil
	}
	if err := s.instances.Terminate(ctx, value(member.Data.InstanceId)); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Service) drainTargets(ctx context.Context, group GroupRecord, member InstanceRecord) (bool, error) {
	drained := true
	for _, target := range group.Data.TargetGroupARNs {
		if err := s.targetGroups.Deregister(ctx, group.Key.ARN(group.ID), string(target), value(member.Data.InstanceId)); err != nil {
			return false, err
		}
		done, err := s.targetGroups.Drained(ctx, group.Key.ARN(group.ID), string(target), value(member.Data.InstanceId))
		if err != nil {
			return false, err
		}
		drained = drained && done
	}
	return drained, nil
}

func (s *Service) drainMembership(ctx context.Context, group GroupRecord, member InstanceRecord, detach bool) (bool, error) {
	drained, err := s.drainTargets(ctx, group, member)
	if err != nil || !drained {
		return false, err
	}
	if detach {
		if err := s.instances.SetGroup(ctx, value(member.Data.InstanceId), ""); err != nil {
			return false, err
		}
	}
	return s.updateMembership(ctx, group, member, func(tx Transaction, g GroupRecord, m InstanceRecord) (bool, error) {
		if detach && !m.DetachRequested || !detach && value(m.Data.LifecycleState) != "EnteringStandby" {
			return false, nil
		}
		if err := s.finishMemberActivity(tx.Context(), tx, g, m, nil); err != nil {
			return false, err
		}
		if detach {
			if err := deleteInstanceActions(tx, g, value(m.Data.InstanceId)); err != nil {
				return false, err
			}
			return true, tx.DeleteInstance(g.Key.Scope, value(m.Data.InstanceId))
		}
		text(&m.Data.LifecycleState, "Standby")
		return true, tx.PutInstance(m)
	})
}
