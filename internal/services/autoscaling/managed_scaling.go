package autoscaling

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/autoscaling"
)

// ErrManagedScaleUp means another capacity increase superseded a managed
// scale-down. The caller must preserve the current group instead of retrying it.
var ErrManagedScaleUp = errors.New("managed Auto Scaling group scaled up")

var errManagedScalingUnchanged = errors.New("managed scaling is already at or below the requested capacity")

// ManagedScalingState observes configuration, membership and the capacity
// ownership counter in one repository snapshot.
type ManagedScalingState struct {
	Group          api.AutoScalingGroup
	ScaleUpVersion uint64
}

func (s *Service) ManagedScaling(ctx context.Context, groupName, groupARN string) (ManagedScalingState, error) {
	var state ManagedScalingState
	err := s.repository.View(ctx, func(tx Reader) error {
		if err := s.authorize(tx.Context(), "DescribeAutoScalingGroups", "*", nil); err != nil {
			return err
		}
		group, err := tx.Group(GroupKey{Scope: scopeFor(ctx), Name: groupName})
		if err != nil {
			return err
		}
		if groupARN != "" && group.Key.ARN(group.ID) != groupARN {
			return failure("ResourceContention", "The managed Auto Scaling group was replaced.")
		}
		state.Group, err = describeGroup(tx, group, true)
		state.ScaleUpVersion = group.ScaleUpVersion
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ManagedScalingState{}, ErrNotFound
		}
		return ManagedScalingState{}, wireError(err)
	}
	return state, nil
}

type managedScalingGuard struct {
	groupARN       string
	scaleUpVersion uint64
}

func (guard managedScalingGuard) check(group GroupRecord) error {
	if group.Key.ARN(group.ID) != guard.groupARN {
		return failure("ResourceContention", "The managed Auto Scaling group was replaced.")
	}
	if group.ScaleUpVersion != guard.scaleUpVersion {
		return errors.Join(ErrManagedScaleUp, failure("ResourceContention", "The managed Auto Scaling group scaled up during scale-down."))
	}
	return nil
}

// UpdateManagedScaling performs the ordinary authorized group update only while
// the observed incarnation and scale-up counter still own the reduction. A
// replay cannot increase either desired capacity or the maximum group size.
func (s *Service) UpdateManagedScaling(ctx context.Context, groupName, groupARN string, expectedScaleUpVersion uint64, desired, maxSize int32) error {
	in := &api.UpdateAutoScalingGroupInput{
		AutoScalingGroupName: new(api.XmlStringMaxLen255(groupName)),
		DesiredCapacity:      new(api.AutoScalingGroupDesiredCapacity(desired)),
		MaxSize:              new(api.AutoScalingGroupMaxSize(maxSize)),
	}
	guard := managedScalingGuard{groupARN: groupARN, scaleUpVersion: expectedScaleUpVersion}
	_, err := executePrepared(s, ctx, "UpdateAutoScalingGroup", in, func(ctx context.Context, in *api.UpdateAutoScalingGroupInput) (func(Transaction) (*api.UpdateAutoScalingGroupOutput, error), error) {
		return s.prepareGroupUpdate(ctx, in, &guard)
	})
	if err == nil || errors.Is(err, errManagedScalingUnchanged) {
		return nil
	}
	if errors.Is(err, ErrManagedScaleUp) {
		return err
	}
	return wireError(err)
}
