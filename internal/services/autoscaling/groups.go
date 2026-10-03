package autoscaling

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
)

func registerGroups(s *Service) {
	registerPrepared(s, "CreateAutoScalingGroup", s.prepareCreateAutoScalingGroup)
	registerPrepared(s, "UpdateAutoScalingGroup", s.prepareUpdateAutoScalingGroup)
	register(s, "DeleteAutoScalingGroup", s.deleteAutoScalingGroup)
	register(s, "DescribeAutoScalingGroups", s.describeAutoScalingGroups)
	register(s, "SetDesiredCapacity", s.setDesiredCapacity)
	register(s, "SuspendProcesses", s.suspendProcesses)
	register(s, "ResumeProcesses", s.resumeProcesses)
	register(s, "DescribeScalingActivities", s.describeScalingActivities)
	register(s, "DescribeScalingProcessTypes", s.describeScalingProcessTypes)
	register(s, "DescribeTerminationPolicyTypes", s.describeTerminationPolicyTypes)
}

func (s *Service) prepareCreateAutoScalingGroup(ctx context.Context, in *api.CreateAutoScalingGroupInput) (func(Transaction) (*api.CreateAutoScalingGroupOutput, error), error) {
	if value(in.InstanceId) != "" || len(in.AvailabilityZoneIds) > 0 || len(in.TrafficSources) > 0 {
		// TODO: Comeback support instance-derived group creation, explicit zone-ID
		// placement and non-ELBv2 traffic-source admission.
		return nil, unsupported("The requested Auto Scaling creation source is not implemented.")
	}
	group := GroupRecord{Key: GroupKey{Scope: scopeFor(ctx), Name: value(in.AutoScalingGroupName)}, ID: uuid.NewString(), OriginEventID: apievents.EventID(ctx)}
	group.Data = api.AutoScalingGroup{
		AutoScalingGroupName: in.AutoScalingGroupName, MinSize: in.MinSize, MaxSize: in.MaxSize, DesiredCapacity: in.DesiredCapacity,
		LaunchTemplate: in.LaunchTemplate, LaunchConfigurationName: in.LaunchConfigurationName,
		AvailabilityZones: in.AvailabilityZones, VPCZoneIdentifier: in.VPCZoneIdentifier,
		DefaultCooldown: in.DefaultCooldown, DefaultInstanceWarmup: in.DefaultInstanceWarmup,
		HealthCheckType: in.HealthCheckType, HealthCheckGracePeriod: in.HealthCheckGracePeriod,
		NewInstancesProtectedFromScaleIn: in.NewInstancesProtectedFromScaleIn, ServiceLinkedRoleARN: in.ServiceLinkedRoleARN,
		TerminationPolicies: in.TerminationPolicies, TargetGroupARNs: in.TargetGroupARNs, LoadBalancerNames: in.LoadBalancerNames,
		AvailabilityZoneDistribution: in.AvailabilityZoneDistribution, AvailabilityZoneImpairmentPolicy: in.AvailabilityZoneImpairmentPolicy,
		CapacityRebalance: in.CapacityRebalance, CapacityReservationSpecification: in.CapacityReservationSpecification,
		Context: in.Context, DesiredCapacityType: in.DesiredCapacityType, DeletionProtection: in.DeletionProtection,
		InstanceLifecyclePolicy: in.InstanceLifecyclePolicy, InstanceMaintenancePolicy: in.InstanceMaintenancePolicy,
		MaxInstanceLifetime: in.MaxInstanceLifetime, MixedInstancesPolicy: in.MixedInstancesPolicy,
		Operator: in.Operator, PlacementGroup: in.PlacementGroup,
		Instances: api.Instances{}, SuspendedProcesses: api.SuspendedProcesses{}, EnabledMetrics: api.EnabledMetrics{}, TrafficSources: api.TrafficSources{},
	}
	text(&group.Data.AutoScalingGroupARN, group.Key.ARN(group.ID))
	group.Data.CreatedTime = new(api.TimestampType(s.clock.Now().UTC()))
	if group.Data.DesiredCapacity == nil {
		number(&group.Data.DesiredCapacity, intValue(in.MinSize))
	}
	if group.Data.DefaultCooldown == nil {
		number(&group.Data.DefaultCooldown, 300)
	}
	if group.Data.HealthCheckGracePeriod == nil {
		number(&group.Data.HealthCheckGracePeriod, 0)
	}
	if group.Data.HealthCheckType == nil {
		text(&group.Data.HealthCheckType, "EC2")
	}
	if group.Data.NewInstancesProtectedFromScaleIn == nil {
		boolean(&group.Data.NewInstancesProtectedFromScaleIn, false)
	}
	if len(group.Data.TerminationPolicies) == 0 {
		group.Data.TerminationPolicies = api.TerminationPolicies{api.XmlStringMaxLen1600("Default")}
	}
	if group.Data.LoadBalancerNames == nil {
		group.Data.LoadBalancerNames = api.LoadBalancerNames{}
	}
	if group.Data.TargetGroupARNs == nil {
		group.Data.TargetGroupARNs = api.TargetGroupARNs{}
	}
	if group.Data.AvailabilityZoneDistribution == nil {
		group.Data.AvailabilityZoneDistribution = &api.AvailabilityZoneDistribution{CapacityDistributionStrategy: new(api.CapacityDistributionStrategy("balanced-best-effort"))}
	}
	if group.Data.CapacityReservationSpecification == nil {
		group.Data.CapacityReservationSpecification = &api.CapacityReservationSpecification{CapacityReservationPreference: new(api.CapacityReservationPreference("default"))}
	}
	if group.Data.InstanceLifecyclePolicy == nil {
		group.Data.InstanceLifecyclePolicy = &api.InstanceLifecyclePolicy{RetentionTriggers: &api.RetentionTriggers{TerminateHookAbandon: new(api.RetentionAction("terminate"))}}
	}
	if group.Data.ServiceLinkedRoleARN == nil {
		text(&group.Data.ServiceLinkedRoleARN, fmt.Sprintf("arn:%s:iam::%s:role/aws-service-role/%s/AWSServiceRoleForAutoScaling", group.Key.Partition, group.Key.AccountID, ServicePrincipal))
	}
	if err := applyGroupTags(&group, in.Tags); err != nil {
		return nil, err
	}
	if err := validateGroupConfiguration(group.Data); err != nil {
		return nil, err
	}
	conditions := groupConditions(group)
	groupRequestConditions(conditions, group.Data)
	requestTagConditions(conditions, in.Tags)
	if err := s.authorize(ctx, "CreateAutoScalingGroup", group.Key.ARN(group.ID), conditions); err != nil {
		return nil, err
	}
	if in.InstanceLifecyclePolicy != nil && !slices.ContainsFunc(in.LifecycleHookSpecificationList, func(hook api.LifecycleHookSpecification) bool {
		return value(hook.LifecycleTransition) == terminateTransition && (hook.DefaultResult == nil || value(hook.DefaultResult) == "ABANDON")
	}) {
		return nil, failure("InvalidQueryParameter", "InstanceLifecyclePolicy requires at least one terminate lifecycle hook with default result ABANDON. Configure a terminate lifecycle hook with ABANDON result, or remove InstanceLifecyclePolicy and try again.")
	}
	if err := s.repository.View(ctx, func(tx Reader) error {
		if _, err := tx.Group(group.Key); err == nil {
			return failure("AlreadyExists", "AutoScalingGroup by this name already exists - A group with the name "+group.Key.Name+" already exists")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if s.roles == nil {
		return nil, unsupported("Auto Scaling service-linked role ownership is not configured.")
	}
	if in.ServiceLinkedRoleARN == nil {
		if err := s.roles.EnsureServiceLinkedRole(ctx, ServicePrincipal); err != nil {
			return nil, err
		}
	} else if err := s.authorizeLinkedRole(ctx, group); err != nil {
		return nil, err
	}
	if _, err := s.resolveGroupPlacement(ctx, &group); err != nil {
		return nil, err
	}
	if err := s.resolveGroupTemplate(ctx, &group); err != nil {
		return nil, err
	}
	if err := s.validateTerminationPolicy(ctx, group); err != nil {
		return nil, err
	}
	return func(tx Transaction) (*api.CreateAutoScalingGroupOutput, error) {
		if _, err := tx.Group(group.Key); err == nil {
			return nil, failure("AlreadyExists", "AutoScalingGroup by this name already exists - A group with the name "+group.Key.Name+" already exists")
		} else if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err := s.requestReconcile(tx, group); err != nil {
			return nil, err
		}
		for _, hook := range in.LifecycleHookSpecificationList {
			if err := s.installLifecycleHook(tx.Context(), tx, group, hook); err != nil {
				return nil, err
			}
		}
		ctx.Value(auditContextKey{}).(*auditContext).GroupID = group.ID
		return &api.CreateAutoScalingGroupOutput{}, nil
	}, nil
}

func (s *Service) prepareUpdateAutoScalingGroup(ctx context.Context, in *api.UpdateAutoScalingGroupInput) (func(Transaction) (*api.UpdateAutoScalingGroupOutput, error), error) {
	return s.prepareGroupUpdate(ctx, in, nil)
}

func (s *Service) prepareGroupUpdate(ctx context.Context, in *api.UpdateAutoScalingGroupInput, guard *managedScalingGuard) (func(Transaction) (*api.UpdateAutoScalingGroupOutput, error), error) {
	var group GroupRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		group, err = tx.Group(GroupKey{Scope: scopeFor(ctx), Name: value(in.AutoScalingGroupName)})
		if errors.Is(err, ErrNotFound) {
			_, err = s.loadGroup(tx.Context(), tx, value(in.AutoScalingGroupName), "UpdateAutoScalingGroup")
		}
		if err != nil {
			return err
		}
		return validateRefreshGroupUpdate(tx, group, in)
	})
	if err != nil {
		return nil, err
	}
	if guard != nil {
		if err := s.authorizeGroupUpdate(ctx, group, in); err != nil {
			return nil, err
		}
		if err := guard.check(group); err != nil {
			return nil, err
		}
	}
	if group.Deleting {
		return nil, failure("ResourceInUse", "The Auto Scaling group is being deleted.")
	}
	if guard != nil {
		if intValue(in.DesiredCapacity) > intValue(group.Data.DesiredCapacity) || intValue(in.MaxSize) > intValue(group.Data.MaxSize) ||
			intValue(in.DesiredCapacity) == intValue(group.Data.DesiredCapacity) && intValue(in.MaxSize) == intValue(group.Data.MaxSize) {
			return nil, errManagedScalingUnchanged
		}
	}
	snapshot := cloneGroup(group)
	if len(in.AvailabilityZoneIds) > 0 {
		return nil, unsupported("Explicit Availability Zone ID placement is not implemented.")
	}
	if in.MinSize != nil {
		group.Data.MinSize = in.MinSize
	}
	if in.MaxSize != nil {
		group.Data.MaxSize = in.MaxSize
	}
	desired := intValue(group.Data.DesiredCapacity)
	if in.DesiredCapacity != nil {
		desired = intValue(in.DesiredCapacity)
	} else {
		// AWS changes omitted desired capacity only when the new bounds exclude it.
		desired = min(max(desired, intValue(group.Data.MinSize)), intValue(group.Data.MaxSize))
	}
	setGroupDesired(&group, desired)
	if in.MinSize != nil || in.MaxSize != nil || in.DesiredCapacity != nil {
		group.PendingInstanceWarmup = nil
	}
	if in.LaunchTemplate != nil {
		group.Data.LaunchTemplate = in.LaunchTemplate
	}
	if in.LaunchConfigurationName != nil {
		group.Data.LaunchConfigurationName = in.LaunchConfigurationName
	}
	if in.VPCZoneIdentifier != nil {
		group.Data.VPCZoneIdentifier = in.VPCZoneIdentifier
		// Stored zones are derived placement, not constraints on a new subnet
		// selection. Explicit zones below still constrain the new subnets.
		group.Data.AvailabilityZones = nil
	}
	if in.AvailabilityZones != nil {
		group.Data.AvailabilityZones = in.AvailabilityZones
	}
	if in.DefaultCooldown != nil {
		group.Data.DefaultCooldown = in.DefaultCooldown
	}
	if in.DefaultInstanceWarmup != nil {
		group.Data.DefaultInstanceWarmup = in.DefaultInstanceWarmup
	}
	if in.HealthCheckGracePeriod != nil {
		group.Data.HealthCheckGracePeriod = in.HealthCheckGracePeriod
	}
	if in.HealthCheckType != nil {
		group.Data.HealthCheckType = in.HealthCheckType
	}
	if in.TerminationPolicies != nil {
		group.Data.TerminationPolicies = in.TerminationPolicies
		if len(group.Data.TerminationPolicies) == 0 {
			group.Data.TerminationPolicies = api.TerminationPolicies{api.XmlStringMaxLen1600("Default")}
		}
	}
	if in.NewInstancesProtectedFromScaleIn != nil {
		group.Data.NewInstancesProtectedFromScaleIn = in.NewInstancesProtectedFromScaleIn
	}
	if in.ServiceLinkedRoleARN != nil {
		group.Data.ServiceLinkedRoleARN = in.ServiceLinkedRoleARN
	}
	if in.AvailabilityZoneDistribution != nil {
		group.Data.AvailabilityZoneDistribution = in.AvailabilityZoneDistribution
	}
	if in.AvailabilityZoneImpairmentPolicy != nil {
		group.Data.AvailabilityZoneImpairmentPolicy = in.AvailabilityZoneImpairmentPolicy
	}
	if in.CapacityRebalance != nil {
		group.Data.CapacityRebalance = in.CapacityRebalance
	}
	if in.CapacityReservationSpecification != nil {
		group.Data.CapacityReservationSpecification = in.CapacityReservationSpecification
	}
	if in.Context != nil {
		group.Data.Context = in.Context
	}
	if in.DeletionProtection != nil {
		group.Data.DeletionProtection = in.DeletionProtection
	}
	if in.DesiredCapacityType != nil {
		group.Data.DesiredCapacityType = in.DesiredCapacityType
	}
	if in.InstanceLifecyclePolicy != nil {
		group.Data.InstanceLifecyclePolicy = in.InstanceLifecyclePolicy
	}
	if in.InstanceMaintenancePolicy != nil {
		group.Data.InstanceMaintenancePolicy = in.InstanceMaintenancePolicy
	}
	if in.MaxInstanceLifetime != nil {
		group.Data.MaxInstanceLifetime = in.MaxInstanceLifetime
	}
	if in.MixedInstancesPolicy != nil {
		group.Data.MixedInstancesPolicy = in.MixedInstancesPolicy
	}
	if in.PlacementGroup != nil {
		text(&group.Data.PlacementGroup, string(*in.PlacementGroup))
	}
	if err := validateGroupConfiguration(group.Data); err != nil {
		return nil, err
	}
	if guard == nil {
		if err := s.authorizeGroupUpdate(ctx, group, in); err != nil {
			return nil, err
		}
	}
	if in.ServiceLinkedRoleARN != nil {
		if err := s.authorizeLinkedRole(ctx, group); err != nil {
			return nil, err
		}
	}
	if in.VPCZoneIdentifier != nil || in.AvailabilityZones != nil {
		if _, err := s.resolveGroupPlacement(ctx, &group); err != nil {
			return nil, err
		}
	}
	if in.LaunchTemplate != nil || in.VPCZoneIdentifier != nil || in.AvailabilityZones != nil {
		if err := s.resolveGroupTemplate(ctx, &group); err != nil {
			return nil, err
		}
	}
	if in.LaunchTemplate != nil && group.Data.WarmPoolConfiguration != nil {
		if err := s.instances.ValidateWarmPool(ctx, group); err != nil {
			return nil, err
		}
	}
	if in.TerminationPolicies != nil || in.ServiceLinkedRoleARN != nil {
		if err := s.validateTerminationPolicy(ctx, group); err != nil {
			return nil, err
		}
	}
	group.OriginEventID = apievents.EventID(ctx)
	return func(tx Transaction) (*api.UpdateAutoScalingGroupOutput, error) {
		current, err := tx.Group(group.Key)
		if errors.Is(err, ErrNotFound) {
			return nil, failure("ResourceContention", "The Auto Scaling group changed while the update was being prepared.")
		}
		if err != nil {
			return nil, err
		}
		if guard != nil {
			if err := guard.check(current); err != nil {
				return nil, err
			}
		}
		if !sameGroupConfiguration(current, snapshot) {
			return nil, failure("ResourceContention", "The Auto Scaling group changed while the update was being prepared.")
		}
		if err = validateRefreshGroupUpdate(tx, current, in); err != nil {
			return nil, err
		}
		// Preparation owns the requested configuration, not the scheduler's
		// version or metric deadline. Admit onto the current row and request a
		// fresh wakeup without restoring stale controller bookkeeping.
		current.Data = group.Data
		current.ScaleUpVersion = group.ScaleUpVersion
		current.PendingInstanceWarmup = group.PendingInstanceWarmup
		current.OriginEventID = group.OriginEventID
		if err = s.requestReconcile(tx, current); err != nil {
			return nil, err
		}
		return &api.UpdateAutoScalingGroupOutput{}, nil
	}, nil
}

func (s *Service) authorizeGroupUpdate(ctx context.Context, group GroupRecord, in *api.UpdateAutoScalingGroupInput) error {
	conditions := groupConditions(group)
	groupRequestConditions(conditions, api.AutoScalingGroup{MinSize: in.MinSize, MaxSize: in.MaxSize, LaunchTemplate: in.LaunchTemplate, VPCZoneIdentifier: in.VPCZoneIdentifier, ServiceLinkedRoleARN: in.ServiceLinkedRoleARN})
	return s.authorize(ctx, "UpdateAutoScalingGroup", group.Key.ARN(group.ID), conditions)
}

// sameGroupConfiguration fences outside-transaction API preparation against
// authoritative group changes. Scheduler generations and publication deadlines
// are deliberately not configuration; callers must commit onto the current row.
func sameGroupConfiguration(current, snapshot GroupRecord) bool {
	current.Version, snapshot.Version = 0, 0
	current.ReconcileAt, snapshot.ReconcileAt = time.Time{}, time.Time{}
	current.MetricAt, snapshot.MetricAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(current, snapshot)
}

func (s *Service) deleteAutoScalingGroup(ctx context.Context, tx Transaction, in *api.DeleteAutoScalingGroupInput) (*api.DeleteAutoScalingGroupOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "DeleteAutoScalingGroup")
	if err != nil {
		return nil, err
	}
	force := in.ForceDelete != nil && bool(*in.ForceDelete)
	protection := value(group.Data.DeletionProtection)
	if protection == "prevent-all-deletion" || protection == "prevent-force-deletion" && force {
		return nil, failure("ResourceInUse", "The Auto Scaling group has deletion protection enabled.")
	}
	if force && retainOnAbandon(group.Data.InstanceLifecyclePolicy) {
		return nil, invalid("You can't force delete this Auto Scaling group because the TerminateHookAbandon retention trigger is set to retain. Change the retention trigger to terminate and try again.")
	}
	members, err := tx.Instances(group.Key)
	if err != nil {
		return nil, err
	}
	if !force && (intValue(group.Data.MinSize) != 0 || intValue(group.Data.DesiredCapacity) != 0 || len(members) > 0) {
		return nil, failure("ResourceInUse", "You cannot delete an AutoScalingGroup while there are instances or the group has nonzero capacity.")
	}
	group.Deleting = true
	group.OriginEventID = apievents.EventID(ctx)
	text(&group.Data.Status, "Delete in progress")
	number(&group.Data.MinSize, 0)
	setGroupDesired(&group, 0)
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.DeleteAutoScalingGroupOutput{}, nil
}

func (s *Service) requestReconcile(tx Transaction, group GroupRecord) error {
	group.Version++
	group.ReconcileAt = s.clock.Now()
	return tx.PutGroup(group)
}

// All changes to an existing group's desired capacity pass through this helper.
// The counter is committed with the group, independently of scheduler wakeups.
func setGroupDesired(group *GroupRecord, desired int64) {
	if desired > intValue(group.Data.DesiredCapacity) {
		group.ScaleUpVersion++
	}
	number(&group.Data.DesiredCapacity, desired)
}

func (s *Service) changeDesired(tx Transaction, group GroupRecord, desired int32, cause string) error {
	if group.Deleting {
		return failure("ResourceInUse", "The Auto Scaling group is being deleted.")
	}
	if err := validateCapacity(intValue(group.Data.MinSize), intValue(group.Data.MaxSize), int64(desired)); err != nil {
		return err
	}
	setGroupDesired(&group, int64(desired))
	if origin := apievents.EventID(tx.Context()); origin != "" {
		group.OriginEventID = origin
	}
	group.ReconcileCause = cause
	return s.requestReconcile(tx, group)
}

func (s *Service) setDesiredCapacity(ctx context.Context, tx Transaction, in *api.SetDesiredCapacityInput) (*api.SetDesiredCapacityOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "SetDesiredCapacity")
	if err != nil {
		return nil, err
	}
	if in.HonorCooldown != nil && bool(*in.HonorCooldown) {
		activities, err := tx.Activities(group.Key.Scope, group.Key.Name, false)
		if err != nil {
			return nil, err
		}
		for _, activity := range activities {
			if activity.Data.EndTime != nil && time.Time(*activity.Data.EndTime).Add(time.Duration(intValue(group.Data.DefaultCooldown))*time.Second).After(s.clock.Now()) {
				return nil, failure("ScalingActivityInProgress", "The Auto Scaling group is in cooldown.")
			}
		}
	}
	group.PendingInstanceWarmup = nil
	if err := s.changeDesired(tx, group, int32(intValue(in.DesiredCapacity)), "User requested capacity change"); err != nil {
		return nil, err
	}
	return &api.SetDesiredCapacityOutput{}, nil
}

func (s *Service) suspendProcesses(ctx context.Context, tx Transaction, in *api.SuspendProcessesInput) (*api.SuspendProcessesOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "SuspendProcesses")
	if err != nil {
		return nil, err
	}
	processes := plainList(in.ScalingProcesses)
	if len(processes) == 0 {
		processes = scalingProcesses
	}
	for _, name := range processes {
		if !slices.Contains(scalingProcesses, name) {
			return nil, invalid("The scaling process is not valid: " + name)
		}
		if !processSuspended(group, name) {
			group.Data.SuspendedProcesses = append(group.Data.SuspendedProcesses, api.SuspendedProcess{ProcessName: new(api.XmlStringMaxLen255(name)), SuspensionReason: new(api.XmlStringMaxLen255("User suspended at " + s.clock.Now().UTC().Format(time.RFC3339)))})
		}
	}
	slices.SortFunc(group.Data.SuspendedProcesses, func(a, b api.SuspendedProcess) int {
		return strings.Compare(value(a.ProcessName), value(b.ProcessName))
	})
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.SuspendProcessesOutput{}, nil
}

func (s *Service) resumeProcesses(ctx context.Context, tx Transaction, in *api.ResumeProcessesInput) (*api.ResumeProcessesOutput, error) {
	group, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "ResumeProcesses")
	if err != nil {
		return nil, err
	}
	processes := plainList(in.ScalingProcesses)
	if len(processes) == 0 {
		processes = scalingProcesses
	}
	for _, name := range processes {
		if !slices.Contains(scalingProcesses, name) {
			return nil, invalid("The scaling process is not valid: " + name)
		}
	}
	if slices.Contains(processes, "ScheduledActions") && processSuspended(group, "ScheduledActions") {
		if err := s.skipSuspendedSchedules(tx, group.Key, s.clock.Now()); err != nil {
			return nil, err
		}
	}
	group.Data.SuspendedProcesses = slices.DeleteFunc(group.Data.SuspendedProcesses, func(p api.SuspendedProcess) bool { return slices.Contains(processes, value(p.ProcessName)) })
	if err := s.requestReconcile(tx, group); err != nil {
		return nil, err
	}
	return &api.ResumeProcessesOutput{}, nil
}
