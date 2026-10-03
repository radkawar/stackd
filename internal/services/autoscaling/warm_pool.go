package autoscaling

import (
	"context"
	"slices"
	"strings"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
)

func registerWarmPool(s *Service) {
	register(s, "PutWarmPool", s.putWarmPool)
	register(s, "DescribeWarmPool", s.describeWarmPool)
	register(s, "DeleteWarmPool", s.deleteWarmPool)
}

func warmMember(member InstanceRecord) bool {
	return strings.HasPrefix(value(member.Data.LifecycleState), "Warmed:")
}

func retainedMember(member InstanceRecord) bool {
	return strings.HasSuffix(value(member.Data.LifecycleState), ":Retained")
}

func warmPoolDeleting(group GroupRecord) bool {
	return group.Data.WarmPoolConfiguration != nil && value(group.Data.WarmPoolConfiguration.Status) == "PendingDelete"
}

func warmPoolDesired(group GroupRecord) int64 {
	pool := group.Data.WarmPoolConfiguration
	if pool == nil || group.Deleting || warmPoolDeleting(group) {
		return 0
	}
	prepared := intValue(group.Data.MaxSize)
	if pool.MaxGroupPreparedCapacity != nil && intValue(pool.MaxGroupPreparedCapacity) >= 0 {
		prepared = intValue(pool.MaxGroupPreparedCapacity)
	}
	return max(intValue(pool.MinSize), prepared-intValue(group.Data.DesiredCapacity))
}

func reuseOnScaleIn(group GroupRecord) bool {
	pool := group.Data.WarmPoolConfiguration
	return pool != nil && !warmPoolDeleting(group) && pool.InstanceReusePolicy != nil && pool.InstanceReusePolicy.ReuseOnScaleIn != nil && bool(*pool.InstanceReusePolicy.ReuseOnScaleIn)
}

func (s *Service) putWarmPool(ctx context.Context, tx Transaction, in *api.PutWarmPoolInput) (*api.PutWarmPoolOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "PutWarmPool")
	if err != nil {
		return nil, err
	}
	if group.Deleting || warmPoolDeleting(group) {
		return nil, invalid("You cannot update a warm pool while it is deleting.")
	}
	pool := group.Data.WarmPoolConfiguration
	if pool == nil {
		pool = &api.WarmPoolConfiguration{MinSize: new(api.WarmPoolMinSize(0)), PoolState: new(api.WarmPoolState("Stopped"))}
	}
	if in.MinSize != nil {
		pool.MinSize = in.MinSize
	}
	if in.MaxGroupPreparedCapacity != nil {
		pool.MaxGroupPreparedCapacity = in.MaxGroupPreparedCapacity
		if intValue(in.MaxGroupPreparedCapacity) == -1 {
			pool.MaxGroupPreparedCapacity = nil
		}
	}
	if in.PoolState != nil {
		pool.PoolState = in.PoolState
	}
	if in.InstanceReusePolicy != nil && in.InstanceReusePolicy.ReuseOnScaleIn != nil {
		pool.InstanceReusePolicy = in.InstanceReusePolicy
	}
	if intValue(pool.MinSize) < 0 || intValue(pool.MaxGroupPreparedCapacity) < -1 {
		return nil, invalid("MinSize must be nonnegative and MaxGroupPreparedCapacity must be at least -1.")
	}
	if pool.MaxGroupPreparedCapacity != nil && intValue(pool.MaxGroupPreparedCapacity) >= 0 && intValue(pool.MaxGroupPreparedCapacity) < intValue(pool.MinSize) {
		return nil, invalid("MaxGroupPreparedCapacity must be greater than or equal to MinSize.")
	}
	if !slices.Contains([]string{"Stopped", "Running", "Hibernated"}, value(pool.PoolState)) {
		return nil, invalid("PoolState must be Stopped, Running, or Hibernated.")
	}
	group.Data.WarmPoolConfiguration = pool
	if err := validateGroupConfiguration(group.Data); err != nil {
		return nil, err
	}
	if s.instances == nil {
		return nil, unsupported("EC2 Auto Scaling execution is not configured.")
	}
	// Configuration reads use the linked role, not caller launch permissions.
	if err := s.instances.ValidateWarmPool(ctx, group); err != nil {
		return nil, err
	}
	group.OriginEventID = apievents.EventID(ctx)
	group.ReconcileCause = "Warm pool configuration updated."
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.PutWarmPoolOutput{}, nil
}

func (s *Service) describeWarmPool(ctx context.Context, tx Transaction, in *api.DescribeWarmPoolInput) (*api.DescribeWarmPoolOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "DescribeWarmPool")
	if err != nil {
		return nil, err
	}
	members, err := tx.Instances(group.Key)
	if err != nil {
		return nil, err
	}
	members = slices.DeleteFunc(members, func(m InstanceRecord) bool { return !warmMember(m) })
	members, next, err := pageRows(scopeFor(ctx), "DescribeWarmPool", group.Key.ARN(group.ID), in.MaxRecords, in.NextToken, members, func(m InstanceRecord) string { return value(m.Data.InstanceId) })
	if err != nil {
		return nil, err
	}
	out := &api.DescribeWarmPoolOutput{WarmPoolConfiguration: group.Data.WarmPoolConfiguration, Instances: api.Instances{}, NextToken: next}
	for _, member := range members {
		data := member.Data
		data.ProtectedFromScaleIn = nil
		out.Instances = append(out.Instances, data)
	}
	return out, nil
}

func (s *Service) deleteWarmPool(ctx context.Context, tx Transaction, in *api.DeleteWarmPoolInput) (*api.DeleteWarmPoolOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "DeleteWarmPool")
	if err != nil {
		return nil, err
	}
	if group.Data.WarmPoolConfiguration == nil {
		return nil, invalid("The Auto Scaling group does not have a warm pool.")
	}
	force := in.ForceDelete != nil && bool(*in.ForceDelete)
	if !force {
		activities, err := tx.Activities(group.Key.Scope, group.Key.Name, false)
		if err != nil {
			return nil, err
		}
		for _, activity := range activities {
			if activity.GroupID == group.ID && activity.Kind == "warm-launch" && activity.InstanceID == "" && activity.Data.EndTime == nil {
				return nil, failure("ScalingActivityInProgress", "The warm pool has a launch in progress.")
			}
		}
	}
	members, err := tx.Instances(group.Key)
	if err != nil {
		return nil, err
	}
	group.OriginEventID = apievents.EventID(ctx)
	for _, member := range members {
		if !warmMember(member) {
			continue
		}
		if !force {
			return nil, failure("ResourceInUse", "The warm pool contains instances. Set its MinSize and MaxGroupPreparedCapacity to zero, or use ForceDelete.")
		}
	}
	number(&group.Data.WarmPoolConfiguration.MinSize, 0)
	number(&group.Data.WarmPoolConfiguration.MaxGroupPreparedCapacity, 0)
	text(&group.Data.WarmPoolConfiguration.Status, "PendingDelete")
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.DeleteWarmPoolOutput{}, nil
}
