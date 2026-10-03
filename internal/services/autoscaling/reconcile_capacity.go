package autoscaling

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	ec2api "stackd/internal/awsapi/ec2"
)

func countsCapacity(member InstanceRecord) bool {
	if warmMember(member) {
		return false
	}
	switch value(member.Data.LifecycleState) {
	case "Standby", "EnteringStandby", "Detaching", "Detached", "Terminating:Retained":
		return false
	default:
		return !member.DetachRequested
	}
}

func (s *Service) reconcileCapacity(ctx context.Context, snapshot GroupRecord) (bool, error) {
	var group GroupRecord
	var members []InstanceRecord
	launch, warmLaunch, changed := false, false, false
	err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		group, err = tx.Group(snapshot.Key)
		if err != nil {
			return err
		}
		members, err = tx.Instances(group.Key)
		return err
	})
	if errors.Is(err, ErrNotFound) || err == nil && (group.ID != snapshot.ID || group.Version != snapshot.Version) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	capacity := int64(0)
	for _, member := range members {
		if countsCapacity(member) && !member.TerminationRequested {
			capacity++
		}
	}
	var selected []InstanceRecord
	if !group.Deleting && capacity > intValue(group.Data.DesiredCapacity) && !processSuspended(group, "Terminate") {
		selected, err = s.selectTerminations(ctx, group, members, "SCALE_IN", capacity-intValue(group.Data.DesiredCapacity), nil)
		if err != nil {
			return false, err
		}
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := terminationSelectionCurrent(tx, group, members)
		if err != nil || !current {
			return err
		}
		if group.Deleting {
			for _, member := range members {
				if !member.TerminationRequested && !member.DetachRequested {
					if _, err := s.terminateMember(tx, group, &member, "Auto Scaling group deletion requested."); err != nil {
						return err
					}
					changed = true
				}
			}
			if len(members) == 0 {
				activities, err := tx.Activities(group.Key.Scope, group.Key.Name, false)
				if err != nil {
					return err
				}
				for _, activity := range activities {
					if activity.Data.EndTime == nil {
						return nil
					}
				}
				policies, err := tx.Policies(group.Key)
				if err != nil {
					return err
				}
				for _, policy := range policies {
					if err := s.deletePolicyAlarms(tx.Context(), group, policy); err != nil {
						return err
					}
				}
				changed = true
				return tx.DeleteGroup(group.Key)
			}
			return nil
		}
		if warmPoolDeleting(group) && !slices.ContainsFunc(members, warmMember) {
			group.Data.WarmPoolConfiguration = nil
			changed = true
			return tx.PutGroup(group)
		}
		capacity := int64(0)
		for _, member := range members {
			if countsCapacity(member) && !member.TerminationRequested {
				capacity++
			}
		}
		desired := intValue(group.Data.DesiredCapacity)
		if capacity > desired && !processSuspended(group, "Terminate") {
			if len(selected) > 0 {
				for _, member := range selected {
					if reuseOnScaleIn(group) && value(member.Data.LifecycleState) == "InService" {
						if err := s.returnToWarmPool(tx, group, member); err != nil {
							return err
						}
					} else if _, err := s.terminateMember(tx, group, &member, group.ReconcileCause); err != nil {
						return err
					}
				}
				changed = true
			} else {
				if lambdaTerminationPolicy(group) != "" && slices.ContainsFunc(members, func(member InstanceRecord) bool {
					return terminationEligible(group, member, "SCALE_IN", nil)
				}) {
					changed, err = s.deferLambdaTermination(tx, group, capacity)
					return err
				}
				// The accepted request and the remaining capacity identify this
				// blocked intent, not the polling version or the passage of time.
				cause := fmt.Sprintf("%s Desired capacity is %d; %d protected instances remain.", group.ReconcileCause, desired, capacity)
				activities, err := tx.Activities(group.Key.Scope, group.Key.Name, false)
				if err != nil {
					return err
				}
				for _, activity := range activities {
					if activity.GroupID == group.ID && activity.Kind == "scale-in" && activity.OriginEventID == group.OriginEventID && value(activity.Data.Cause) == cause && value(activity.Data.StatusCode) == "Cancelled" {
						return nil
					}
				}
				activity := s.newActivity(group, "scale-in", cause)
				text(&activity.Data.Description, "Could not scale to desired capacity because all remaining instances are protected from scale-in.")
				text(&activity.Data.Details, "{}")
				if err := s.cancelActivity(tx.Context(), tx, group, activity, ""); err != nil {
					return err
				}
				changed = true
			}
		}
		launch = capacity < desired && !processSuspended(group, "Launch")
		if changed {
			return nil
		}
		if launch {
			for _, member := range members {
				if !warmPoolDeleting(group) && warmReady(member) && !member.TerminationRequested && value(member.Data.HealthStatus) != "Unhealthy" {
					if err := s.activateWarmMember(tx, group, member); err != nil {
						return err
					}
					changed = true
					return nil
				}
			}
			return nil
		}
		warmed := int64(0)
		for _, member := range members {
			if warmMember(member) && !member.TerminationRequested && !retainedMember(member) {
				warmed++
			}
		}
		prepared := warmPoolDesired(group)
		if capacity < desired && !warmPoolDeleting(group) {
			// Launch suspension reserves warm capacity for the pending scale-out.
			// Do not retire those guests merely because desired capacity rose.
			prepared += desired - capacity
		}
		if warmed > prepared && !processSuspended(group, "Terminate") {
			if member, ok := chooseWarmTermination(group, members, s.clock.Now()); ok {
				if _, err := s.terminateMember(tx, group, &member, "Reducing warm pool capacity."); err != nil {
					return err
				}
				changed = true
			}
		}
		warmLaunch = warmed < prepared && !processSuspended(group, "Launch")
		launch = warmLaunch
		return nil
	})
	if err != nil || changed || !launch {
		return changed, err
	}
	kind := "launch"
	if warmLaunch {
		kind = "warm-launch"
	}
	// Select template/network facts outside the ASG write transaction. Recheck the
	// group version before accepting this exact immutable EC2 launch intent.
	launchGroup, err := s.refreshLaunchGroup(ctx, group)
	if err != nil {
		return false, err
	}
	spec, err := s.instances.Template(ctx, *launchGroup.Data.LaunchTemplate)
	if err != nil {
		return false, s.failedLaunchIntent(ctx, group, kind, err)
	}
	subnets, err := s.instances.Placement(ctx, strings.Split(value(group.Data.VPCZoneIdentifier), ","), nil)
	if err != nil {
		return false, s.failedLaunchIntent(ctx, group, kind, err)
	}
	if len(subnets) == 0 {
		return false, s.failedLaunchIntent(ctx, group, kind, invalid("The Auto Scaling group has no usable subnets."))
	}
	// TODO: Comeback implement AZRebalance when capacity already equals desired,
	// and balanced-best-effort fallback when the least-populated zone cannot launch.
	zoneCounts := map[string]int{}
	for _, member := range members {
		if countsCapacity(member) {
			zoneCounts[value(member.Data.AvailabilityZone)]++
		}
	}
	slices.SortFunc(subnets, func(a, b ec2api.Subnet) int {
		return cmp.Or(cmp.Compare(zoneCounts[value(a.AvailabilityZone)], zoneCounts[value(b.AvailabilityZone)]), strings.Compare(value(a.AvailabilityZone), value(b.AvailabilityZone)), strings.Compare(value(a.SubnetId), value(b.SubnetId)))
	})
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Group(group.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != group.ID || current.Version != group.Version {
			return nil
		}
		activity := s.newActivity(current, kind, current.ReconcileCause)
		if warmLaunch {
			activity.WarmPoolState = value(current.Data.WarmPoolConfiguration.PoolState)
		}
		activity.LaunchTemplate = spec
		activity.SubnetID = value(subnets[0].SubnetId)
		activity.InstanceWarmup = launchGroup.PendingInstanceWarmup
		activity.ProtectedFromScaleIn = current.Data.NewInstancesProtectedFromScaleIn != nil && bool(*current.Data.NewInstancesProtectedFromScaleIn)
		for _, tag := range current.Data.Tags {
			if tag.PropagateAtLaunch != nil && bool(*tag.PropagateAtLaunch) {
				activity.LaunchTags = append(activity.LaunchTags, tag)
			}
		}
		text(&activity.Data.Description, "Launching a new EC2 instance.")
		return tx.PutActivity(activity)
	})
	return err == nil, err
}

func (s *Service) failedLaunchIntent(ctx context.Context, group GroupRecord, kind string, cause error) error {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Group(group.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ID != group.ID || current.Version != group.Version {
			return nil
		}
		activity := s.newActivity(current, kind, current.ReconcileCause)
		return s.finishActivity(tx.Context(), tx, current, activity, cause)
	})
	if err != nil {
		return err
	}
	return cause
}

func chooseWarmTermination(group GroupRecord, members []InstanceRecord, now time.Time) (InstanceRecord, bool) {
	zoneCounts := map[string]int{}
	candidates := make([]InstanceRecord, 0, len(members))
	for _, member := range members {
		if !warmMember(member) || retainedMember(member) {
			continue
		}
		zoneCounts[value(member.Data.AvailabilityZone)]++
		if !member.TerminationRequested {
			candidates = append(candidates, member)
		}
	}
	if len(candidates) == 0 {
		return InstanceRecord{}, false
	}
	policies := []string{"Default"}
	slices.SortFunc(candidates, func(a, b InstanceRecord) int {
		if order := cmp.Compare(zoneCounts[value(b.Data.AvailabilityZone)], zoneCounts[value(a.Data.AvailabilityZone)]); order != 0 {
			return order
		}
		return compareTerminationPolicies(group, a, b, policies, now)
	})
	return candidates[0], true
}

func compareTerminationPolicies(group GroupRecord, a, b InstanceRecord, policies []string, now time.Time) int {
	for _, policy := range policies {
		var order int
		switch policy {
		case "OldestInstance":
			order = a.JoinedAt.Compare(b.JoinedAt)
		case "NewestInstance":
			order = b.JoinedAt.Compare(a.JoinedAt)
		case "OldestLaunchTemplate":
			order = compareLaunchAge(group, a, b)
		case "ClosestToNextInstanceHour":
			order = cmp.Compare(time.Hour-now.Sub(a.JoinedAt)%time.Hour, time.Hour-now.Sub(b.JoinedAt)%time.Hour)
		case "Default":
			order = cmp.Or(compareLaunchAge(group, a, b), cmp.Compare(time.Hour-now.Sub(a.JoinedAt)%time.Hour, time.Hour-now.Sub(b.JoinedAt)%time.Hour))
		}
		if order != 0 {
			return order
		}
	}
	return strings.Compare(value(a.Data.InstanceId), value(b.Data.InstanceId))
}

func compareLaunchAge(group GroupRecord, a, b InstanceRecord) int {
	current := value(group.Data.LaunchTemplate.LaunchTemplateId)
	age := func(member InstanceRecord) (int, int64) {
		if member.Data.LaunchTemplate == nil {
			return 0, 0
		}
		spec := member.Data.LaunchTemplate
		version, _ := strconv.ParseInt(value(spec.Version), 10, 64)
		if value(spec.LaunchTemplateId) != current {
			return 1, version
		}
		return 2, version
	}
	ak, av := age(a)
	bk, bv := age(b)
	return cmp.Or(cmp.Compare(ak, bk), cmp.Compare(av, bv))
}
