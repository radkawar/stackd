package autoscaling

import (
	"fmt"
	api "stackd/internal/awsapi/autoscaling"
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
)

func (r reader) group(row sqlcgen.AsgGroup) (domain.GroupRecord, error) {
	out := domain.GroupRecord{
		Key:                   groupKey(row.Partition, row.AccountID, row.Region, row.Name),
		ID:                    row.NativeID,
		OriginEventID:         row.OriginEventID,
		Deleting:              row.Deleting,
		ReconcileAt:           row.ReconcileAt.Time,
		ReconcileCause:        row.ReconcileCause,
		PendingInstanceWarmup: intPointer[int32](row.PendingInstanceWarmup),
		MetricAt:              row.MetricAt.Time,
		Version:               uint64(row.Version),
		ScaleUpVersion:        uint64(row.ScaleUpVersion),
	}
	out.Data.AutoScalingGroupARN = stringPointer[api.ResourceName](row.DataAutoScalingGroupArn)
	out.Data.AutoScalingGroupName = stringPointer[api.XmlStringMaxLen255](row.DataAutoScalingGroupName)
	if row.HasDataAvailabilityZoneDistribution {
		out.Data.AvailabilityZoneDistribution = &api.AvailabilityZoneDistribution{}
	}
	if out.Data.AvailabilityZoneDistribution != nil {
		out.Data.AvailabilityZoneDistribution.CapacityDistributionStrategy = stringPointer[api.CapacityDistributionStrategy](row.DataAvailabilityZoneDistributionCapacityDistributionStrategy)
	}
	if row.HasDataAvailabilityZoneIds {
		var err error
		out.Data.AvailabilityZoneIds, err = r.readGroupsAvailabilityZoneIds(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	if row.HasDataAvailabilityZones {
		var err error
		out.Data.AvailabilityZones, err = r.readGroupsAvailabilityZones(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	out.Data.CapacityRebalance = boolPointer[api.CapacityRebalanceEnabled](row.DataCapacityRebalance)
	if row.HasDataCapacityReservationSpecification {
		out.Data.CapacityReservationSpecification = &api.CapacityReservationSpecification{}
	}
	if out.Data.CapacityReservationSpecification != nil {
		out.Data.CapacityReservationSpecification.CapacityReservationPreference = stringPointer[api.CapacityReservationPreference](row.DataCapacityReservationSpecificationCapacityReservationPreference)
	}
	if out.Data.CapacityReservationSpecification != nil {
		if row.HasDataCapacityReservationSpecificationCapacityReservationTarget {
			out.Data.CapacityReservationSpecification.CapacityReservationTarget = &api.CapacityReservationTarget{}
		}
	}
	if out.Data.CapacityReservationSpecification != nil && out.Data.CapacityReservationSpecification.CapacityReservationTarget != nil {
		if row.HasDataCapacityReservationSpecificationCapacityReservationTargetCapacityReservationIds {
			var err error
			out.Data.CapacityReservationSpecification.CapacityReservationTarget.CapacityReservationIds, err = r.readGroupsCapacityReservationIds(row.GroupPk)
			if err != nil {
				return domain.GroupRecord{}, err
			}
		}
	}
	if out.Data.CapacityReservationSpecification != nil && out.Data.CapacityReservationSpecification.CapacityReservationTarget != nil {
		if row.HasDataCapacityReservationSpecificationCapacityReservationTargetCapacityReservationResourceGroupArns {
			var err error
			out.Data.CapacityReservationSpecification.CapacityReservationTarget.CapacityReservationResourceGroupArns, err = r.readGroupsCapacityReservationResourceGroupArns(row.GroupPk)
			if err != nil {
				return domain.GroupRecord{}, err
			}
		}
	}
	out.Data.Context = stringPointer[api.Context](row.DataContext)
	out.Data.CreatedTime = timePointer(row.DataCreatedTime)
	out.Data.DefaultCooldown = intPointer[api.Cooldown](row.DataDefaultCooldown)
	out.Data.DefaultInstanceWarmup = intPointer[api.DefaultInstanceWarmup](row.DataDefaultInstanceWarmup)
	out.Data.DeletionProtection = stringPointer[api.DeletionProtection](row.DataDeletionProtection)
	out.Data.DesiredCapacity = intPointer[api.AutoScalingGroupDesiredCapacity](row.DataDesiredCapacity)
	out.Data.DesiredCapacityType = stringPointer[api.XmlStringMaxLen255](row.DataDesiredCapacityType)
	if row.HasDataEnabledMetrics {
		var err error
		out.Data.EnabledMetrics, err = r.readGroupsEnabledMetrics(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	out.Data.HealthCheckGracePeriod = intPointer[api.HealthCheckGracePeriod](row.DataHealthCheckGracePeriod)
	out.Data.HealthCheckType = stringPointer[api.XmlStringMaxLen32](row.DataHealthCheckType)
	if row.HasDataInstanceLifecyclePolicy {
		out.Data.InstanceLifecyclePolicy = &api.InstanceLifecyclePolicy{}
	}
	if out.Data.InstanceLifecyclePolicy != nil {
		if row.HasDataInstanceLifecyclePolicyRetentionTriggers {
			out.Data.InstanceLifecyclePolicy.RetentionTriggers = &api.RetentionTriggers{}
		}
	}
	if out.Data.InstanceLifecyclePolicy != nil && out.Data.InstanceLifecyclePolicy.RetentionTriggers != nil {
		out.Data.InstanceLifecyclePolicy.RetentionTriggers.TerminateHookAbandon = stringPointer[api.RetentionAction](row.DataInstanceLifecyclePolicyRetentionTriggersTerminateHookAbandon)
	}
	out.Data.LaunchConfigurationName = stringPointer[api.XmlStringMaxLen255](row.DataLaunchConfigurationName)
	if row.HasDataLaunchTemplate {
		out.Data.LaunchTemplate = &api.LaunchTemplateSpecification{}
	}
	if out.Data.LaunchTemplate != nil {
		out.Data.LaunchTemplate.LaunchTemplateId = stringPointer[api.XmlStringMaxLen255](row.DataLaunchTemplateLaunchTemplateID)
	}
	if out.Data.LaunchTemplate != nil {
		out.Data.LaunchTemplate.LaunchTemplateName = stringPointer[api.LaunchTemplateName](row.DataLaunchTemplateLaunchTemplateName)
	}
	if out.Data.LaunchTemplate != nil {
		out.Data.LaunchTemplate.Version = stringPointer[api.XmlStringMaxLen255](row.DataLaunchTemplateVersion)
	}
	if row.HasDataLoadBalancerNames {
		var err error
		out.Data.LoadBalancerNames, err = r.readGroupsLoadBalancerNames(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	out.Data.MaxInstanceLifetime = intPointer[api.MaxInstanceLifetime](row.DataMaxInstanceLifetime)
	out.Data.MaxSize = intPointer[api.AutoScalingGroupMaxSize](row.DataMaxSize)
	out.Data.MinSize = intPointer[api.AutoScalingGroupMinSize](row.DataMinSize)
	out.Data.NewInstancesProtectedFromScaleIn = boolPointer[api.InstanceProtected](row.DataNewInstancesProtectedFromScaleIn)
	out.Data.PlacementGroup = stringPointer[api.XmlStringMaxLen255](row.DataPlacementGroup)
	out.Data.PredictedCapacity = intPointer[api.AutoScalingGroupPredictedCapacity](row.DataPredictedCapacity)
	out.Data.ServiceLinkedRoleARN = stringPointer[api.ResourceName](row.DataServiceLinkedRoleArn)
	out.Data.Status = stringPointer[api.XmlStringMaxLen255](row.DataStatus)
	if row.HasDataSuspendedProcesses {
		var err error
		out.Data.SuspendedProcesses, err = r.readGroupsSuspendedProcesses(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	if row.HasDataTags {
		var err error
		out.Data.Tags, err = r.readGroupsTags(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	if row.HasDataTargetGroupArns {
		var err error
		out.Data.TargetGroupARNs, err = r.readGroupsTargetGroupArns(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	if row.HasDataTerminationPolicies {
		var err error
		out.Data.TerminationPolicies, err = r.readGroupsTerminationPolicies(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	if row.HasDataTrafficSources {
		var err error
		out.Data.TrafficSources, err = r.readGroupsTrafficSources(row.GroupPk)
		if err != nil {
			return domain.GroupRecord{}, err
		}
	}
	out.Data.VPCZoneIdentifier = stringPointer[api.XmlStringMaxLen5000](row.DataVpcZoneIdentifier)
	out.Data.WarmPoolSize = intPointer[api.WarmPoolSize](row.DataWarmPoolSize)
	if row.HasDataWarmPoolConfiguration {
		out.Data.WarmPoolConfiguration = &api.WarmPoolConfiguration{
			MinSize:                  intPointer[api.WarmPoolMinSize](row.DataWarmPoolConfigurationMinSize),
			MaxGroupPreparedCapacity: intPointer[api.MaxGroupPreparedCapacity](row.DataWarmPoolConfigurationMaxGroupPreparedCapacity),
			PoolState:                stringPointer[api.WarmPoolState](row.DataWarmPoolConfigurationPoolState),
			Status:                   stringPointer[api.WarmPoolStatus](row.DataWarmPoolConfigurationStatus),
		}
		if row.HasDataWarmPoolConfigurationInstanceReusePolicy {
			out.Data.WarmPoolConfiguration.InstanceReusePolicy = &api.InstanceReusePolicy{
				ReuseOnScaleIn: boolPointer[api.ReuseOnScaleIn](row.DataWarmPoolConfigurationInstanceReusePolicyReuseOnScaleIn),
			}
		}
	}
	return out, nil
}

func (w writer) PutGroup(v domain.GroupRecord) error {
	if v.Data.AvailabilityZoneImpairmentPolicy != nil {
		return fmt.Errorf("autoscaling storage: unsupported AvailabilityZoneImpairmentPolicy configuration")
	}
	if v.Data.InstanceMaintenancePolicy != nil {
		return fmt.Errorf("autoscaling storage: unsupported InstanceMaintenancePolicy configuration")
	}
	if v.Data.MixedInstancesPolicy != nil {
		return fmt.Errorf("autoscaling storage: unsupported MixedInstancesPolicy configuration")
	}
	if v.Data.Operator != nil {
		return fmt.Errorf("autoscaling storage: unsupported Operator configuration")
	}
	p := sqlcgen.PutGroupParams{
		Partition:             v.Key.Partition,
		AccountID:             v.Key.AccountID,
		Region:                v.Key.Region,
		Name:                  v.Key.Name,
		NativeID:              v.ID,
		OriginEventID:         v.OriginEventID,
		Deleting:              v.Deleting,
		ReconcileAt:           deadline(v.ReconcileAt),
		ReconcileCause:        v.ReconcileCause,
		PendingInstanceWarmup: nullableInt(v.PendingInstanceWarmup),
		MetricAt:              deadline(v.MetricAt),
		Version:               sqlite.Uint64(v.Version),
		ScaleUpVersion:        sqlite.Uint64(v.ScaleUpVersion),
	}
	p.DataAutoScalingGroupArn = nullableString(v.Data.AutoScalingGroupARN)
	p.DataAutoScalingGroupName = nullableString(v.Data.AutoScalingGroupName)
	p.HasDataAvailabilityZoneDistribution = v.Data.AvailabilityZoneDistribution != nil
	if v.Data.AvailabilityZoneDistribution != nil {
		p.DataAvailabilityZoneDistributionCapacityDistributionStrategy = nullableString(v.Data.AvailabilityZoneDistribution.CapacityDistributionStrategy)
	}
	p.HasDataAvailabilityZoneIds = v.Data.AvailabilityZoneIds != nil
	p.HasDataAvailabilityZones = v.Data.AvailabilityZones != nil
	p.DataCapacityRebalance = nullableBool(v.Data.CapacityRebalance)
	p.HasDataCapacityReservationSpecification = v.Data.CapacityReservationSpecification != nil
	if v.Data.CapacityReservationSpecification != nil {
		p.DataCapacityReservationSpecificationCapacityReservationPreference = nullableString(v.Data.CapacityReservationSpecification.CapacityReservationPreference)
	}
	if v.Data.CapacityReservationSpecification != nil {
		p.HasDataCapacityReservationSpecificationCapacityReservationTarget = v.Data.CapacityReservationSpecification.CapacityReservationTarget != nil
	}
	if v.Data.CapacityReservationSpecification != nil && v.Data.CapacityReservationSpecification.CapacityReservationTarget != nil {
		p.HasDataCapacityReservationSpecificationCapacityReservationTargetCapacityReservationIds = v.Data.CapacityReservationSpecification.CapacityReservationTarget.CapacityReservationIds != nil
	}
	if v.Data.CapacityReservationSpecification != nil && v.Data.CapacityReservationSpecification.CapacityReservationTarget != nil {
		p.HasDataCapacityReservationSpecificationCapacityReservationTargetCapacityReservationResourceGroupArns = v.Data.CapacityReservationSpecification.CapacityReservationTarget.CapacityReservationResourceGroupArns != nil
	}
	p.DataContext = nullableString(v.Data.Context)
	p.DataCreatedTime = nullableTime(v.Data.CreatedTime)
	p.DataDefaultCooldown = nullableInt(v.Data.DefaultCooldown)
	p.DataDefaultInstanceWarmup = nullableInt(v.Data.DefaultInstanceWarmup)
	p.DataDeletionProtection = nullableString(v.Data.DeletionProtection)
	p.DataDesiredCapacity = nullableInt(v.Data.DesiredCapacity)
	p.DataDesiredCapacityType = nullableString(v.Data.DesiredCapacityType)
	p.HasDataEnabledMetrics = v.Data.EnabledMetrics != nil
	p.DataHealthCheckGracePeriod = nullableInt(v.Data.HealthCheckGracePeriod)
	p.DataHealthCheckType = nullableString(v.Data.HealthCheckType)
	p.HasDataInstanceLifecyclePolicy = v.Data.InstanceLifecyclePolicy != nil
	if v.Data.InstanceLifecyclePolicy != nil {
		p.HasDataInstanceLifecyclePolicyRetentionTriggers = v.Data.InstanceLifecyclePolicy.RetentionTriggers != nil
	}
	if v.Data.InstanceLifecyclePolicy != nil && v.Data.InstanceLifecyclePolicy.RetentionTriggers != nil {
		p.DataInstanceLifecyclePolicyRetentionTriggersTerminateHookAbandon = nullableString(v.Data.InstanceLifecyclePolicy.RetentionTriggers.TerminateHookAbandon)
	}
	p.DataLaunchConfigurationName = nullableString(v.Data.LaunchConfigurationName)
	p.HasDataLaunchTemplate = v.Data.LaunchTemplate != nil
	if v.Data.LaunchTemplate != nil {
		p.DataLaunchTemplateLaunchTemplateID = nullableString(v.Data.LaunchTemplate.LaunchTemplateId)
	}
	if v.Data.LaunchTemplate != nil {
		p.DataLaunchTemplateLaunchTemplateName = nullableString(v.Data.LaunchTemplate.LaunchTemplateName)
	}
	if v.Data.LaunchTemplate != nil {
		p.DataLaunchTemplateVersion = nullableString(v.Data.LaunchTemplate.Version)
	}
	p.HasDataLoadBalancerNames = v.Data.LoadBalancerNames != nil
	p.DataMaxInstanceLifetime = nullableInt(v.Data.MaxInstanceLifetime)
	p.DataMaxSize = nullableInt(v.Data.MaxSize)
	p.DataMinSize = nullableInt(v.Data.MinSize)
	p.DataNewInstancesProtectedFromScaleIn = nullableBool(v.Data.NewInstancesProtectedFromScaleIn)
	p.DataPlacementGroup = nullableString(v.Data.PlacementGroup)
	p.DataPredictedCapacity = nullableInt(v.Data.PredictedCapacity)
	p.DataServiceLinkedRoleArn = nullableString(v.Data.ServiceLinkedRoleARN)
	p.DataStatus = nullableString(v.Data.Status)
	p.HasDataSuspendedProcesses = v.Data.SuspendedProcesses != nil
	p.HasDataTags = v.Data.Tags != nil
	p.HasDataTargetGroupArns = v.Data.TargetGroupARNs != nil
	p.HasDataTerminationPolicies = v.Data.TerminationPolicies != nil
	p.HasDataTrafficSources = v.Data.TrafficSources != nil
	p.DataVpcZoneIdentifier = nullableString(v.Data.VPCZoneIdentifier)
	p.DataWarmPoolSize = nullableInt(v.Data.WarmPoolSize)
	p.HasDataWarmPoolConfiguration = v.Data.WarmPoolConfiguration != nil
	if pool := v.Data.WarmPoolConfiguration; pool != nil {
		p.DataWarmPoolConfigurationMinSize = nullableInt(pool.MinSize)
		p.DataWarmPoolConfigurationMaxGroupPreparedCapacity = nullableInt(pool.MaxGroupPreparedCapacity)
		p.DataWarmPoolConfigurationPoolState = nullableString(pool.PoolState)
		p.DataWarmPoolConfigurationStatus = nullableString(pool.Status)
		p.HasDataWarmPoolConfigurationInstanceReusePolicy = pool.InstanceReusePolicy != nil
		if pool.InstanceReusePolicy != nil {
			p.DataWarmPoolConfigurationInstanceReusePolicyReuseOnScaleIn = nullableBool(pool.InstanceReusePolicy.ReuseOnScaleIn)
		}
	}
	groupPK, err := w.q.PutGroup(w.ctx, p)
	if err != nil {
		return err
	}
	if err := w.putGroupsAvailabilityZoneIds(groupPK, v.Data.AvailabilityZoneIds); err != nil {
		return err
	}
	if err := w.putGroupsAvailabilityZones(groupPK, v.Data.AvailabilityZones); err != nil {
		return err
	}
	if v.Data.CapacityReservationSpecification != nil && v.Data.CapacityReservationSpecification.CapacityReservationTarget != nil {
		if err := w.putGroupsCapacityReservationIds(groupPK, v.Data.CapacityReservationSpecification.CapacityReservationTarget.CapacityReservationIds); err != nil {
			return err
		}
	} else if err := w.q.DeleteGroupsCapacityReservationIds(w.ctx, groupPK); err != nil {
		return err
	}
	if v.Data.CapacityReservationSpecification != nil && v.Data.CapacityReservationSpecification.CapacityReservationTarget != nil {
		if err := w.putGroupsCapacityReservationResourceGroupArns(groupPK, v.Data.CapacityReservationSpecification.CapacityReservationTarget.CapacityReservationResourceGroupArns); err != nil {
			return err
		}
	} else if err := w.q.DeleteGroupsCapacityReservationResourceGroupArns(w.ctx, groupPK); err != nil {
		return err
	}
	if err := w.putGroupsEnabledMetrics(groupPK, v.Data.EnabledMetrics); err != nil {
		return err
	}
	if err := w.putGroupsLoadBalancerNames(groupPK, v.Data.LoadBalancerNames); err != nil {
		return err
	}
	if err := w.putGroupsSuspendedProcesses(groupPK, v.Data.SuspendedProcesses); err != nil {
		return err
	}
	if err := w.putGroupsTags(groupPK, v.Data.Tags); err != nil {
		return err
	}
	if err := w.putGroupsTargetGroupArns(groupPK, v.Data.TargetGroupARNs); err != nil {
		return err
	}
	if err := w.putGroupsTerminationPolicies(groupPK, v.Data.TerminationPolicies); err != nil {
		return err
	}
	if err := w.putGroupsTrafficSources(groupPK, v.Data.TrafficSources); err != nil {
		return err
	}
	return nil
}

func (r reader) readGroupsAvailabilityZoneIds(parentID int64) (api.AvailabilityZoneIds, error) {
	rows, err := r.q.ListGroupsAvailabilityZoneIds(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.AvailabilityZoneIds, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.XmlStringMaxLen255(row.Value))
	}
	return out, nil
}

func (w writer) putGroupsAvailabilityZoneIds(parentID int64, values api.AvailabilityZoneIds) error {
	if err := w.q.DeleteGroupsAvailabilityZoneIds(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsAvailabilityZoneIdsParams{GroupPk: parentID, Position: int64(position)}
		p.Value = string(item)
		if err := w.q.InsertGroupsAvailabilityZoneIds(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsAvailabilityZones(parentID int64) (api.AvailabilityZones, error) {
	rows, err := r.q.ListGroupsAvailabilityZones(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.AvailabilityZones, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.XmlStringMaxLen255(row.Value))
	}
	return out, nil
}

func (w writer) putGroupsAvailabilityZones(parentID int64, values api.AvailabilityZones) error {
	if err := w.q.DeleteGroupsAvailabilityZones(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsAvailabilityZonesParams{GroupPk: parentID, Position: int64(position)}
		p.Value = string(item)
		if err := w.q.InsertGroupsAvailabilityZones(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsCapacityReservationIds(parentID int64) (api.CapacityReservationIds, error) {
	rows, err := r.q.ListGroupsCapacityReservationIds(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.CapacityReservationIds, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.AsciiStringMaxLen255(row.Value))
	}
	return out, nil
}

func (w writer) putGroupsCapacityReservationIds(parentID int64, values api.CapacityReservationIds) error {
	if err := w.q.DeleteGroupsCapacityReservationIds(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsCapacityReservationIdsParams{GroupPk: parentID, Position: int64(position)}
		p.Value = string(item)
		if err := w.q.InsertGroupsCapacityReservationIds(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsCapacityReservationResourceGroupArns(parentID int64) (api.CapacityReservationResourceGroupArns, error) {
	rows, err := r.q.ListGroupsCapacityReservationResourceGroupArns(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.CapacityReservationResourceGroupArns, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.ResourceName(row.Value))
	}
	return out, nil
}

func (w writer) putGroupsCapacityReservationResourceGroupArns(parentID int64, values api.CapacityReservationResourceGroupArns) error {
	if err := w.q.DeleteGroupsCapacityReservationResourceGroupArns(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsCapacityReservationResourceGroupArnsParams{GroupPk: parentID, Position: int64(position)}
		p.Value = string(item)
		if err := w.q.InsertGroupsCapacityReservationResourceGroupArns(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsEnabledMetrics(parentID int64) (api.EnabledMetrics, error) {
	rows, err := r.q.ListGroupsEnabledMetrics(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.EnabledMetrics, 0, len(rows))
	for _, row := range rows {
		var item api.EnabledMetric
		item.Granularity = stringPointer[api.XmlStringMaxLen255](row.ItemGranularity)
		item.Metric = stringPointer[api.XmlStringMaxLen255](row.ItemMetric)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putGroupsEnabledMetrics(parentID int64, values api.EnabledMetrics) error {
	if err := w.q.DeleteGroupsEnabledMetrics(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsEnabledMetricsParams{GroupPk: parentID, Position: int64(position)}
		p.ItemGranularity = nullableString(item.Granularity)
		p.ItemMetric = nullableString(item.Metric)
		if err := w.q.InsertGroupsEnabledMetrics(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsLoadBalancerNames(parentID int64) (api.LoadBalancerNames, error) {
	rows, err := r.q.ListGroupsLoadBalancerNames(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.LoadBalancerNames, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.XmlStringMaxLen255(row.Value))
	}
	return out, nil
}

func (w writer) putGroupsLoadBalancerNames(parentID int64, values api.LoadBalancerNames) error {
	if err := w.q.DeleteGroupsLoadBalancerNames(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsLoadBalancerNamesParams{GroupPk: parentID, Position: int64(position)}
		p.Value = string(item)
		if err := w.q.InsertGroupsLoadBalancerNames(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsSuspendedProcesses(parentID int64) (api.SuspendedProcesses, error) {
	rows, err := r.q.ListGroupsSuspendedProcesses(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.SuspendedProcesses, 0, len(rows))
	for _, row := range rows {
		var item api.SuspendedProcess
		item.ProcessName = stringPointer[api.XmlStringMaxLen255](row.ItemProcessName)
		item.SuspensionReason = stringPointer[api.XmlStringMaxLen255](row.ItemSuspensionReason)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putGroupsSuspendedProcesses(parentID int64, values api.SuspendedProcesses) error {
	if err := w.q.DeleteGroupsSuspendedProcesses(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsSuspendedProcessesParams{GroupPk: parentID, Position: int64(position)}
		p.ItemProcessName = nullableString(item.ProcessName)
		p.ItemSuspensionReason = nullableString(item.SuspensionReason)
		if err := w.q.InsertGroupsSuspendedProcesses(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsTags(parentID int64) (api.TagDescriptionList, error) {
	rows, err := r.q.ListGroupsTags(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.TagDescriptionList, 0, len(rows))
	for _, row := range rows {
		var item api.TagDescription
		item.Key = stringPointer[api.TagKey](row.ItemKey)
		item.PropagateAtLaunch = boolPointer[api.PropagateAtLaunch](row.ItemPropagateAtLaunch)
		item.ResourceId = stringPointer[api.XmlString](row.ItemResourceID)
		item.ResourceType = stringPointer[api.XmlString](row.ItemResourceType)
		item.Value = stringPointer[api.TagValue](row.ItemValue)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putGroupsTags(parentID int64, values api.TagDescriptionList) error {
	if err := w.q.DeleteGroupsTags(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsTagsParams{GroupPk: parentID, Position: int64(position)}
		p.ItemKey = nullableString(item.Key)
		p.ItemPropagateAtLaunch = nullableBool(item.PropagateAtLaunch)
		p.ItemResourceID = nullableString(item.ResourceId)
		p.ItemResourceType = nullableString(item.ResourceType)
		p.ItemValue = nullableString(item.Value)
		if err := w.q.InsertGroupsTags(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsTargetGroupArns(parentID int64) (api.TargetGroupARNs, error) {
	rows, err := r.q.ListGroupsTargetGroupArns(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.TargetGroupARNs, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.XmlStringMaxLen511(row.Value))
	}
	return out, nil
}

func (w writer) putGroupsTargetGroupArns(parentID int64, values api.TargetGroupARNs) error {
	if err := w.q.DeleteGroupsTargetGroupArns(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsTargetGroupArnsParams{GroupPk: parentID, Position: int64(position)}
		p.Value = string(item)
		if err := w.q.InsertGroupsTargetGroupArns(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsTerminationPolicies(parentID int64) (api.TerminationPolicies, error) {
	rows, err := r.q.ListGroupsTerminationPolicies(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.TerminationPolicies, 0, len(rows))
	for _, row := range rows {
		out = append(out, api.XmlStringMaxLen1600(row.Value))
	}
	return out, nil
}

func (w writer) putGroupsTerminationPolicies(parentID int64, values api.TerminationPolicies) error {
	if err := w.q.DeleteGroupsTerminationPolicies(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsTerminationPoliciesParams{GroupPk: parentID, Position: int64(position)}
		p.Value = string(item)
		if err := w.q.InsertGroupsTerminationPolicies(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readGroupsTrafficSources(parentID int64) (api.TrafficSources, error) {
	rows, err := r.q.ListGroupsTrafficSources(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.TrafficSources, 0, len(rows))
	for _, row := range rows {
		var item api.TrafficSourceIdentifier
		item.Identifier = stringPointer[api.XmlStringMaxLen511](row.ItemIdentifier)
		item.Type = stringPointer[api.XmlStringMaxLen511](row.ItemType)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putGroupsTrafficSources(parentID int64, values api.TrafficSources) error {
	if err := w.q.DeleteGroupsTrafficSources(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertGroupsTrafficSourcesParams{GroupPk: parentID, Position: int64(position)}
		p.ItemIdentifier = nullableString(item.Identifier)
		p.ItemType = nullableString(item.Type)
		if err := w.q.InsertGroupsTrafficSources(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}
