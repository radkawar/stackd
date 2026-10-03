package autoscaling

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/autoscaling"
	ec2api "stackd/internal/awsapi/ec2"
)

var terminationPolicies = []string{"AllocationStrategy", "ClosestToNextInstanceHour", "Default", "Lambda", "NewestInstance", "OldestInstance", "OldestLaunchConfiguration", "OldestLaunchTemplate"}
var scalingProcesses = []string{"AZRebalance", "AddToLoadBalancer", "AlarmNotification", "HealthCheck", "InstanceRefresh", "Launch", "ReplaceUnhealthy", "ScheduledActions", "Terminate"}

func validateCapacity(minimum, maximum, desired int64) error {
	if minimum < 0 || maximum < 0 || desired < 0 || minimum > maximum {
		return invalid("MinSize must be nonnegative and must not be greater than MaxSize.")
	}
	if desired < minimum || desired > maximum {
		return invalid(fmt.Sprintf("Desired capacity:%d must be between the specified min size:%d and max size:%d", desired, minimum, maximum))
	}
	return nil
}

func validateGroupConfiguration(data api.AutoScalingGroup) error {
	if err := validateCapacity(intValue(data.MinSize), intValue(data.MaxSize), intValue(data.DesiredCapacity)); err != nil {
		return err
	}
	if value(data.AutoScalingGroupName) == "" || strings.Contains(value(data.AutoScalingGroupName), ":") || !utf8.ValidString(value(data.AutoScalingGroupName)) {
		return invalid("The Auto Scaling group name is not valid.")
	}
	if data.LaunchTemplate == nil {
		return invalid("A launch template must be specified.")
	}
	if value(data.LaunchTemplate.LaunchTemplateId) == "" && value(data.LaunchTemplate.LaunchTemplateName) == "" {
		return invalid("A launch template ID or name must be specified.")
	}
	if intValue(data.DefaultCooldown) < 0 || intValue(data.HealthCheckGracePeriod) < 0 || intValue(data.DefaultInstanceWarmup) < -1 {
		return invalid("Cooldown, health check grace period and instance warmup values are not valid.")
	}
	if lifetime := intValue(data.MaxInstanceLifetime); lifetime != 0 && lifetime < 86400 {
		return invalid("MaxInstanceLifetime must be 0 or at least 86400 seconds.")
	}
	switch value(data.HealthCheckType) {
	case "EC2", "ELB":
	default:
		return unsupported("This Auto Scaling health check type is not implemented.")
	}
	switch value(data.DeletionProtection) {
	case "", "none", "prevent-all-deletion", "prevent-force-deletion":
	default:
		return invalid("The deletion protection setting is not valid.")
	}
	if err := validateTerminationPolicies(data); err != nil {
		return err
	}
	if data.AvailabilityZoneDistribution != nil {
		switch value(data.AvailabilityZoneDistribution.CapacityDistributionStrategy) {
		case "balanced-best-effort", "balanced-only":
		default:
			return invalid("The capacity distribution strategy is not valid.")
		}
	}
	if data.InstanceLifecyclePolicy != nil && data.InstanceLifecyclePolicy.RetentionTriggers != nil {
		switch value(data.InstanceLifecyclePolicy.RetentionTriggers.TerminateHookAbandon) {
		case "terminate", "retain":
		default:
			return invalid("The lifecycle retention trigger is not valid.")
		}
	}
	// TODO: Comeback support mixed/Spot capacity, reservations, placement groups,
	// maintenance percentages, impairment controls and non-instance capacity units.
	if data.MixedInstancesPolicy != nil || data.AvailabilityZoneImpairmentPolicy != nil || data.InstanceMaintenancePolicy != nil || data.Operator != nil || value(data.PlacementGroup) != "" || data.CapacityRebalance != nil && bool(*data.CapacityRebalance) || value(data.DesiredCapacityType) != "" && value(data.DesiredCapacityType) != "units" {
		return unsupported("The requested advanced Auto Scaling capacity configuration is not implemented.")
	}
	if reservation := data.CapacityReservationSpecification; reservation != nil && (reservation.CapacityReservationTarget != nil || value(reservation.CapacityReservationPreference) != "default") {
		return unsupported("Auto Scaling capacity reservation selection is not implemented.")
	}
	if value(data.LaunchConfigurationName) != "" || len(data.LoadBalancerNames) > 0 {
		return unsupported("Legacy launch configurations and Classic Load Balancers are not implemented.")
	}
	return nil
}

// resolveGroupPlacement asks the EC2 owner for scoped subnet/zone facts. The
// service stores the native normalized selection, not a second network model.
func (s *Service) resolveGroupPlacement(ctx context.Context, group *GroupRecord) ([]ec2api.Subnet, error) {
	if s.instances == nil || s.identity == nil {
		return nil, unsupported("EC2 Auto Scaling execution is not configured.")
	}
	execution, err := s.identity.Context(ctx, *group)
	if err != nil {
		return nil, err
	}
	var subnetIDs []string
	if raw := value(group.Data.VPCZoneIdentifier); raw != "" {
		for _, id := range strings.Split(raw, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				return nil, invalid("The subnet selection contains an empty subnet ID.")
			}
			subnetIDs = append(subnetIDs, id)
		}
	}
	subnets, err := s.instances.Placement(execution, subnetIDs, plainList(group.Data.AvailabilityZones))
	if err != nil {
		return nil, err
	}
	if len(subnets) == 0 {
		return nil, invalid("At least one subnet or Availability Zone must be specified.")
	}
	subnetIDs = subnetIDs[:0]
	zones := []string{}
	zoneIDs := []string{}
	vpc := value(subnets[0].VpcId)
	for _, subnet := range subnets {
		if value(subnet.VpcId) != vpc {
			return nil, invalid("All subnets must belong to the same VPC.")
		}
		subnetIDs = append(subnetIDs, value(subnet.SubnetId))
		zones = append(zones, value(subnet.AvailabilityZone))
		zoneIDs = append(zoneIDs, value(subnet.AvailabilityZoneId))
	}
	slices.Sort(subnetIDs)
	subnetIDs = slices.Compact(subnetIDs)
	slices.Sort(zones)
	zones = slices.Compact(zones)
	slices.Sort(zoneIDs)
	zoneIDs = slices.Compact(zoneIDs)
	group.Data.AvailabilityZones = make(api.AvailabilityZones, len(zones))
	for i, zone := range zones {
		group.Data.AvailabilityZones[i] = api.XmlStringMaxLen255(zone)
	}
	group.Data.AvailabilityZoneIds = make(api.AvailabilityZoneIds, len(zoneIDs))
	for i, zone := range zoneIDs {
		group.Data.AvailabilityZoneIds[i] = api.XmlStringMaxLen255(zone)
	}
	text(&group.Data.VPCZoneIdentifier, strings.Join(subnetIDs, ","))
	if len(group.Data.TargetGroupARNs) > 0 {
		if s.targetGroups == nil {
			return nil, unsupported("Auto Scaling target group integration is not configured.")
		}
		if err := s.targetGroups.Validate(execution, plainList(group.Data.TargetGroupARNs), subnets); err != nil {
			return nil, err
		}
	}
	return subnets, nil
}

func (s *Service) resolveGroupTemplate(ctx context.Context, group *GroupRecord) error {
	execution, err := s.identity.Context(ctx, *group)
	if err != nil {
		return err
	}
	spec, err := s.instances.Template(execution, *group.Data.LaunchTemplate)
	if err != nil {
		return err
	}
	// Resolve existence/identity now but retain the requested alias: later scale
	// events intentionally see a changed $Latest/$Default version.
	version := value(group.Data.LaunchTemplate.Version)
	if version == "" {
		version = "$Default"
	}
	text(&spec.Version, version)
	group.Data.LaunchTemplate = &spec
	return s.instances.Admit(ctx, *group)
}
