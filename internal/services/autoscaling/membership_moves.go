package autoscaling

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
)

func (s *Service) attachInstances(ctx context.Context, tx Transaction, in *api.AttachInstancesInput) (*api.AttachInstancesOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "AttachInstances")
	if err != nil {
		return nil, err
	}
	if group.Deleting {
		return nil, failure("ResourceInUse", "The Auto Scaling group is being deleted.")
	}
	if processSuspended(group, "Launch") {
		return nil, invalid("Instances cannot be attached while the Launch process is suspended.")
	}
	ids := listSelection(in.InstanceIds)
	if len(ids) == 0 {
		return nil, invalid("At least one instance ID must be specified.")
	}
	desired := intValue(group.Data.DesiredCapacity) + int64(len(ids))
	if err := validateCapacity(intValue(group.Data.MinSize), intValue(group.Data.MaxSize), desired); err != nil {
		return nil, err
	}
	execution, err := s.identity.Context(ctx, group)
	if err != nil {
		return nil, err
	}
	observations, err := s.instances.Observe(execution, ids)
	if err != nil {
		return nil, err
	}
	if len(observations) != len(ids) {
		return nil, invalid("One or more instances do not exist.")
	}
	placement, err := s.instances.Placement(execution, strings.Split(value(group.Data.VPCZoneIdentifier), ","), plainList(group.Data.AvailabilityZones))
	if err != nil {
		return nil, err
	}
	group.OriginEventID = apievents.EventID(ctx)
	for _, observation := range observations {
		instance := observation.Instance
		id := value(instance.InstanceId)
		if _, err := tx.Instance(group.Key.Scope, id); err == nil {
			return nil, invalid("Instance " + id + " is already part of an Auto Scaling group.")
		} else if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if instance.State == nil || value(instance.State.Name) != "running" {
			return nil, invalid("Only running instances can be attached to an Auto Scaling group.")
		}
		if instance.Placement == nil || !slices.Contains(group.Data.AvailabilityZones, api.XmlStringMaxLen255(value(instance.Placement.AvailabilityZone))) {
			return nil, invalid("The instance is not in an Availability Zone configured for the Auto Scaling group.")
		}
		if len(placement) == 0 || value(instance.VpcId) != value(placement[0].VpcId) {
			return nil, invalid("The instance is not in the VPC configured for the Auto Scaling group.")
		}
		if err := s.instances.SetGroup(execution, id, group.Key.ARN(group.ID)); err != nil {
			return nil, err
		}
		member := membershipFromInstance(group, instance, s.clock.Now())
		if instance.LaunchTime != nil {
			member.JoinedAt = *instance.LaunchTime
		}
		activity := s.newActivity(group, "attach", "EC2 instance attachment requested by the user.")
		activity.InstanceID = id
		text(&activity.Data.Description, "Attaching EC2 instance: "+id)
		member.ActivityID = activity.Key.ID
		boolean(&member.Data.ProtectedFromScaleIn, group.Data.NewInstancesProtectedFromScaleIn != nil && bool(*group.Data.NewInstancesProtectedFromScaleIn))
		if err := tx.PutActivity(activity); err != nil {
			return nil, err
		}
		if err := tx.PutInstance(member); err != nil {
			return nil, err
		}
	}
	setGroupDesired(&group, desired)
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.AttachInstancesOutput{}, nil
}

func (s *Service) moveMembers(ctx context.Context, tx Transaction, group GroupRecord, ids []string, decrement bool, kind string) (api.Activities, error) {
	members, err := selectMembers(tx, group, ids)
	if err != nil {
		return nil, err
	}
	desired := intValue(group.Data.DesiredCapacity)
	if decrement {
		if kind == "detach" {
			if err := validateRetainedDecrement(members, "detached"); err != nil {
				return nil, err
			}
		}
		desired -= int64(len(members))
	}
	if kind == "exit-standby" {
		desired += int64(len(members))
	}
	if err := validateCapacity(intValue(group.Data.MinSize), intValue(group.Data.MaxSize), desired); err != nil {
		return nil, err
	}
	group.OriginEventID = apievents.EventID(ctx)
	out := api.Activities{}
	for _, member := range members {
		state := value(member.Data.LifecycleState)
		if member.TerminationRequested || member.DetachRequested {
			return nil, failure("ScalingActivityInProgress", "The instance is leaving the Auto Scaling group.")
		}
		if kind == "standby" && state != "InService" || kind == "exit-standby" && state != "Standby" {
			return nil, invalid("The instance is not in the required lifecycle state.")
		}
		if kind == "detach" && state != "InService" && state != "Standby" && state != "Terminating:Retained" {
			return nil, invalid("Only InService, Standby or retained instances can be detached.")
		}
		if err := s.finishMemberActivity(ctx, tx, group, member, nil); err != nil {
			return nil, err
		}
		activity := s.newActivity(group, kind, "Instance membership change requested by the user.")
		activity.InstanceID = value(member.Data.InstanceId)
		text(&activity.Data.Description, kind+" EC2 instance: "+activity.InstanceID)
		member.ActivityID = activity.Key.ID
		switch kind {
		case "detach":
			member.DetachRequested = true
			text(&member.Data.LifecycleState, "Detaching")
		case "standby":
			text(&member.Data.LifecycleState, "EnteringStandby")
		case "exit-standby":
			text(&member.Data.LifecycleState, "Pending")
			text(&member.Data.HealthStatus, "Healthy")
			member.InServiceAt = time.Time{}
			member.WarmUntil = time.Time{}
			member.HealthCheckGraceIgnored = false
		}
		if err := tx.PutActivity(activity); err != nil {
			return nil, err
		}
		if err := tx.PutInstance(member); err != nil {
			return nil, err
		}
		out = append(out, activity.Data)
	}
	setGroupDesired(&group, desired)
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) detachInstances(ctx context.Context, tx Transaction, in *api.DetachInstancesInput) (*api.DetachInstancesOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "DetachInstances")
	if err != nil {
		return nil, err
	}
	activities, err := s.moveMembers(ctx, tx, group, plainList(in.InstanceIds), in.ShouldDecrementDesiredCapacity != nil && bool(*in.ShouldDecrementDesiredCapacity), "detach")
	if err != nil {
		return nil, err
	}
	return &api.DetachInstancesOutput{Activities: activities}, nil
}
func (s *Service) enterStandby(ctx context.Context, tx Transaction, in *api.EnterStandbyInput) (*api.EnterStandbyOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "EnterStandby")
	if err != nil {
		return nil, err
	}
	activities, err := s.moveMembers(ctx, tx, group, plainList(in.InstanceIds), in.ShouldDecrementDesiredCapacity != nil && bool(*in.ShouldDecrementDesiredCapacity), "standby")
	if err != nil {
		return nil, err
	}
	return &api.EnterStandbyOutput{Activities: activities}, nil
}
func (s *Service) exitStandby(ctx context.Context, tx Transaction, in *api.ExitStandbyInput) (*api.ExitStandbyOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "ExitStandby")
	if err != nil {
		return nil, err
	}
	if processSuspended(group, "Launch") {
		return nil, invalid("Instances cannot exit Standby while the Launch process is suspended.")
	}
	activities, err := s.moveMembers(ctx, tx, group, plainList(in.InstanceIds), false, "exit-standby")
	if err != nil {
		return nil, err
	}
	return &api.ExitStandbyOutput{Activities: activities}, nil
}
