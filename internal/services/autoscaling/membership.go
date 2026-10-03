package autoscaling

import (
	"context"
	"errors"
	"slices"
	"strings"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
)

func registerMembership(s *Service) {
	register(s, "DescribeAutoScalingInstances", s.describeAutoScalingInstances)
	register(s, "SetInstanceProtection", s.setInstanceProtection)
	register(s, "SetInstanceHealth", s.setInstanceHealth)
	register(s, "TerminateInstanceInAutoScalingGroup", s.terminateInstanceInAutoScalingGroup)
	register(s, "AttachInstances", s.attachInstances)
	register(s, "DetachInstances", s.detachInstances)
	register(s, "EnterStandby", s.enterStandby)
	register(s, "ExitStandby", s.exitStandby)
}

func selectMembers(tx Reader, group GroupRecord, ids []string) ([]InstanceRecord, error) {
	if len(ids) == 0 {
		return nil, invalid("At least one instance ID must be specified.")
	}
	out := make([]InstanceRecord, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		member, err := tx.Instance(group.Key.Scope, id)
		if errors.Is(err, ErrNotFound) {
			return nil, invalid("Instance " + id + " is not part of the Auto Scaling group.")
		}
		if err != nil {
			return nil, err
		}
		if member.Group != group.Key || member.GroupID != group.ID {
			return nil, invalid("Instance " + id + " is not part of the Auto Scaling group.")
		}
		out = append(out, member)
	}
	return out, nil
}

func (s *Service) describeAutoScalingInstances(ctx context.Context, tx Transaction, in *api.DescribeAutoScalingInstancesInput) (*api.DescribeAutoScalingInstancesOutput, error) {
	if err := s.authorize(ctx, "DescribeAutoScalingInstances", "*", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	keys, err := tx.GroupKeys(scope.Partition, scope.AccountID)
	if err != nil {
		return nil, err
	}
	ids := listSelection(in.InstanceIds)
	members := []InstanceRecord{}
	for _, key := range keys {
		if key.Scope != scope {
			continue
		}
		rows, err := tx.Instances(key)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if len(ids) == 0 || slices.Contains(ids, value(row.Data.InstanceId)) {
				members = append(members, row)
			}
		}
	}
	members, next, err := pageRows(scope, "DescribeAutoScalingInstances", ids, in.MaxRecords, in.NextToken, members, func(m InstanceRecord) string { return value(m.Data.InstanceId) })
	if err != nil {
		return nil, err
	}
	out := &api.DescribeAutoScalingInstancesOutput{AutoScalingInstances: api.AutoScalingInstances{}, NextToken: next}
	for _, member := range members {
		data := member.Data
		text(&data.HealthStatus, strings.ToUpper(value(data.HealthStatus)))
		out.AutoScalingInstances = append(out.AutoScalingInstances, api.AutoScalingInstanceDetails{AutoScalingGroupName: new(api.XmlStringMaxLen255(member.Group.Name)), AvailabilityZone: data.AvailabilityZone, AvailabilityZoneId: data.AvailabilityZoneId, HealthStatus: data.HealthStatus, ImageId: data.ImageId, InstanceId: data.InstanceId, InstanceType: data.InstanceType, LaunchConfigurationName: data.LaunchConfigurationName, LaunchTemplate: data.LaunchTemplate, LifecycleState: new(api.XmlStringMaxLen32(value(data.LifecycleState))), ProtectedFromScaleIn: data.ProtectedFromScaleIn, WeightedCapacity: data.WeightedCapacity})
	}
	return out, nil
}

func (s *Service) setInstanceProtection(ctx context.Context, tx Transaction, in *api.SetInstanceProtectionInput) (*api.SetInstanceProtectionOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "SetInstanceProtection")
	if err != nil {
		return nil, err
	}
	members, err := selectMembers(tx, group, plainList(in.InstanceIds))
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		if member.TerminationRequested || member.DetachRequested {
			return nil, failure("ScalingActivityInProgress", "The instance is leaving the Auto Scaling group.")
		}
		switch value(member.Data.LifecycleState) {
		case "InService", "EnteringStandby", "Standby":
		default:
			if audit, ok := ctx.Value(auditContextKey{}).(*auditContext); ok {
				audit.ProtectionStateRejected = true
			}
			return nil, invalid("The instance " + value(member.Data.InstanceId) + " is not in InService or EnteringStandby or Standby.")
		}
		boolean(&member.Data.ProtectedFromScaleIn, in.ProtectedFromScaleIn != nil && bool(*in.ProtectedFromScaleIn))
		if err := tx.PutInstance(member); err != nil {
			return nil, err
		}
	}
	group.OriginEventID = apievents.EventID(ctx)
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.SetInstanceProtectionOutput{}, nil
}

func (s *Service) setInstanceHealth(ctx context.Context, tx Transaction, in *api.SetInstanceHealthInput) (*api.SetInstanceHealthOutput, error) {
	status := value(in.HealthStatus)
	if status != "Healthy" && status != "Unhealthy" {
		return nil, invalid("HealthStatus must be Healthy or Unhealthy.")
	}
	member, err := tx.Instance(scopeFor(ctx), value(in.InstanceId))
	if errors.Is(err, ErrNotFound) {
		return nil, invalid("The instance is not part of an Auto Scaling group.")
	}
	if err != nil {
		return nil, err
	}
	group, err := s.loadGroup(ctx, tx, member.Group.Name, "SetInstanceHealth")
	if err != nil {
		return nil, err
	}
	if member.TerminationRequested {
		return nil, failure("ScalingActivityInProgress", "The instance is being terminated.")
	}
	text(&member.Data.HealthStatus, status)
	member.HealthCheckGraceIgnored = status == "Unhealthy" && in.ShouldRespectGracePeriod != nil && !bool(*in.ShouldRespectGracePeriod)
	if err := tx.PutInstance(member); err != nil {
		return nil, err
	}
	group.OriginEventID = apievents.EventID(ctx)
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.SetInstanceHealthOutput{}, nil
}

func (s *Service) terminateInstanceInAutoScalingGroup(ctx context.Context, tx Transaction, in *api.TerminateInstanceInAutoScalingGroupInput) (*api.TerminateInstanceInAutoScalingGroupOutput, error) {
	ids := plainList(in.InstanceIds)
	multiple := len(ids) > 0
	if value(in.InstanceId) != "" {
		if multiple {
			return nil, invalid("Specify InstanceId or InstanceIds, not both.")
		}
		ids = []string{value(in.InstanceId)}
	}
	if len(ids) == 0 || multiple && value(in.AutoScalingGroupName) == "" {
		return nil, invalid("An instance ID, or instance IDs with an Auto Scaling group name, must be specified.")
	}
	name := value(in.AutoScalingGroupName)
	if name == "" {
		member, err := tx.Instance(scopeFor(ctx), ids[0])
		if errors.Is(err, ErrNotFound) {
			return nil, invalid("The instance is not part of an Auto Scaling group.")
		}
		if err != nil {
			return nil, err
		}
		name = member.Group.Name
	}
	group, err := s.loadGroup(ctx, tx, name, "TerminateInstanceInAutoScalingGroup")
	if err != nil {
		return nil, err
	}
	members, err := selectMembers(tx, group, ids)
	if err != nil {
		return nil, err
	}
	if in.ShouldDecrementDesiredCapacity != nil && bool(*in.ShouldDecrementDesiredCapacity) {
		if err := validateRetainedDecrement(members, "terminated"); err != nil {
			return nil, err
		}
		desired := intValue(group.Data.DesiredCapacity) - int64(len(members))
		if err := validateCapacity(intValue(group.Data.MinSize), intValue(group.Data.MaxSize), desired); err != nil {
			return nil, err
		}
		setGroupDesired(&group, desired)
	}
	group.OriginEventID = apievents.EventID(ctx)
	out := &api.TerminateInstanceInAutoScalingGroupOutput{}
	for _, member := range members {
		if member.TerminationRequested || member.DetachRequested {
			return nil, failure("ScalingActivityInProgress", "The instance is already leaving the Auto Scaling group.")
		}
		activity, err := s.terminateMember(tx, group, &member, "Instance termination requested by the user.")
		if err != nil {
			return nil, err
		}
		if multiple {
			out.Activities = append(out.Activities, activity.Data)
		} else {
			out.Activity = &activity.Data
		}
	}
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return out, nil
}

func validateRetainedDecrement(members []InstanceRecord, action string) error {
	for _, member := range members {
		if retainedMember(member) || warmMember(member) {
			return invalid("The instance " + value(member.Data.InstanceId) + " is in a Retained state and can't be " + action + " while decreasing desired capacity. Retry without decreasing the Auto Scaling group's desired capacity.")
		}
	}
	return nil
}
