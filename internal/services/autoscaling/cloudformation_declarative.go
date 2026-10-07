package autoscaling

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/autoscaling"
)

type scalingPolicyARNKey struct{}

// WithScalingPolicyARN fences a trusted consumer's name-based PutScalingPolicy
// against the immutable ARN it read. Public native requests remain upserts.
func WithScalingPolicyARN(ctx context.Context, expectedARN string) context.Context {
	return context.WithValue(ctx, scalingPolicyARNKey{}, expectedARN)
}

// GroupUpdateRemovals identifies fields removed from a declarative group model.
// Capacity bounds remain required; omitted DesiredCapacity keeps native clamping.
// Request-only SkipZonalShiftValidation has no persisted setting to remove.
type GroupUpdateRemovals struct {
	LaunchTemplate, LaunchConfigurationName, MixedInstancesPolicy                     bool
	VPCZoneIdentifier, AvailabilityZones, AvailabilityZoneIds                         bool
	DefaultCooldown, DefaultInstanceWarmup, HealthCheckType, HealthCheckGracePeriod   bool
	TerminationPolicies, NewInstancesProtectedFromScaleIn, ServiceLinkedRoleARN       bool
	AvailabilityZoneDistribution, AvailabilityZoneImpairmentPolicy                    bool
	CapacityRebalance, CapacityReservationSpecification, Context, DesiredCapacityType bool
	DeletionProtection, InstanceLifecyclePolicy, InstanceMaintenancePolicy            bool
	MaxInstanceLifetime, PlacementGroup                                               bool
}

type groupUpdateRemovalsKey struct{}

// WithGroupUpdateRemovals is a trusted consumer seam, not a public API reset mode.
// The ordinary UpdateAutoScalingGroup request continues to merge omitted fields.
func WithGroupUpdateRemovals(ctx context.Context, removed GroupUpdateRemovals) context.Context {
	return context.WithValue(ctx, groupUpdateRemovalsKey{}, removed)
}

func groupUpdateRemovals(ctx context.Context) GroupUpdateRemovals {
	removed, _ := ctx.Value(groupUpdateRemovalsKey{}).(GroupUpdateRemovals)
	return removed
}

// applyGroupDefaults is shared by native creation and declarative removal. It
// deliberately excludes DesiredCapacity, whose update omission is not a reset.
func applyGroupDefaults(group *GroupRecord) {
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
}

func (removed GroupUpdateRemovals) apply(group *GroupRecord) {
	if removed.LaunchTemplate {
		group.Data.LaunchTemplate = nil
	}
	if removed.LaunchConfigurationName {
		group.Data.LaunchConfigurationName = nil
	}
	if removed.MixedInstancesPolicy {
		group.Data.MixedInstancesPolicy = nil
	}
	if removed.VPCZoneIdentifier {
		group.Data.VPCZoneIdentifier = nil
		// Both zone lists are normalized placement, not old-mode constraints.
		group.Data.AvailabilityZones = nil
		group.Data.AvailabilityZoneIds = nil
	}
	if removed.AvailabilityZones {
		group.Data.AvailabilityZones = nil
		group.Data.AvailabilityZoneIds = nil
	}
	if removed.AvailabilityZoneIds {
		group.Data.AvailabilityZoneIds = nil
	}
	if removed.DefaultCooldown {
		group.Data.DefaultCooldown = nil
	}
	if removed.DefaultInstanceWarmup {
		group.Data.DefaultInstanceWarmup = nil
	}
	if removed.HealthCheckType {
		group.Data.HealthCheckType = nil
	}
	if removed.HealthCheckGracePeriod {
		group.Data.HealthCheckGracePeriod = nil
	}
	if removed.TerminationPolicies {
		group.Data.TerminationPolicies = nil
	}
	if removed.NewInstancesProtectedFromScaleIn {
		group.Data.NewInstancesProtectedFromScaleIn = nil
	}
	if removed.ServiceLinkedRoleARN {
		group.Data.ServiceLinkedRoleARN = nil
	}
	if removed.AvailabilityZoneDistribution {
		group.Data.AvailabilityZoneDistribution = nil
	}
	if removed.AvailabilityZoneImpairmentPolicy {
		group.Data.AvailabilityZoneImpairmentPolicy = nil
	}
	if removed.CapacityRebalance {
		group.Data.CapacityRebalance = nil
	}
	if removed.CapacityReservationSpecification {
		group.Data.CapacityReservationSpecification = nil
	}
	if removed.Context {
		group.Data.Context = nil
	}
	if removed.DesiredCapacityType {
		group.Data.DesiredCapacityType = nil
	}
	if removed.DeletionProtection {
		group.Data.DeletionProtection = nil
	}
	if removed.InstanceLifecyclePolicy {
		group.Data.InstanceLifecyclePolicy = nil
	}
	if removed.InstanceMaintenancePolicy {
		group.Data.InstanceMaintenancePolicy = nil
	}
	if removed.MaxInstanceLifetime {
		group.Data.MaxInstanceLifetime = nil
	}
	if removed.PlacementGroup {
		group.Data.PlacementGroup = nil
	}
	applyGroupDefaults(group)
}
