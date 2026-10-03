package autoscaling

import (
	api "stackd/internal/awsapi/autoscaling"
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
)

func (r reader) instance(row sqlcgen.AsgInstance) (domain.InstanceRecord, error) {
	out := domain.InstanceRecord{
		Group:                   groupKey(row.Partition, row.AccountID, row.Region, row.GroupName),
		GroupID:                 row.GroupID,
		JoinedAt:                row.JoinedAt.Time,
		InServiceAt:             row.InServiceAt.Time,
		WarmUntil:               row.WarmUntil.Time,
		ActivityID:              row.ActivityID,
		TerminationRequested:    row.TerminationRequested,
		DetachRequested:         row.DetachRequested,
		HealthCheckGraceIgnored: row.HealthCheckGraceIgnored,
	}
	out.Data.AvailabilityZone = stringPointer[api.XmlStringMaxLen255](row.DataAvailabilityZone)
	out.Data.AvailabilityZoneId = stringPointer[api.XmlStringMaxLen255](row.DataAvailabilityZoneID)
	out.Data.HealthStatus = stringPointer[api.XmlStringMaxLen32](row.DataHealthStatus)
	out.Data.ImageId = stringPointer[api.XmlStringMaxLen255](row.DataImageID)
	out.Data.InstanceId = stringPointer[api.XmlStringMaxLen19](row.DataInstanceID)
	out.Data.InstanceType = stringPointer[api.XmlStringMaxLen255](row.DataInstanceType)
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
	out.Data.LifecycleState = stringPointer[api.LifecycleState](row.DataLifecycleState)
	out.Data.ProtectedFromScaleIn = boolPointer[api.InstanceProtected](row.DataProtectedFromScaleIn)
	out.Data.WeightedCapacity = stringPointer[api.XmlStringMaxLen32](row.DataWeightedCapacity)
	return out, nil
}

func (w writer) PutInstance(v domain.InstanceRecord) error {
	p := sqlcgen.PutInstanceParams{
		Partition:               v.Group.Partition,
		AccountID:               v.Group.AccountID,
		Region:                  v.Group.Region,
		InstanceID:              value(v.Data.InstanceId),
		GroupName:               v.Group.Name,
		GroupID:                 v.GroupID,
		JoinedAt:                deadline(v.JoinedAt),
		InServiceAt:             deadline(v.InServiceAt),
		WarmUntil:               deadline(v.WarmUntil),
		ActivityID:              v.ActivityID,
		TerminationRequested:    v.TerminationRequested,
		DetachRequested:         v.DetachRequested,
		HealthCheckGraceIgnored: v.HealthCheckGraceIgnored,
	}
	p.DataAvailabilityZone = nullableString(v.Data.AvailabilityZone)
	p.DataAvailabilityZoneID = nullableString(v.Data.AvailabilityZoneId)
	p.DataHealthStatus = nullableString(v.Data.HealthStatus)
	p.DataImageID = nullableString(v.Data.ImageId)
	p.DataInstanceID = nullableString(v.Data.InstanceId)
	p.DataInstanceType = nullableString(v.Data.InstanceType)
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
	p.DataLifecycleState = nullableString(v.Data.LifecycleState)
	p.DataProtectedFromScaleIn = nullableBool(v.Data.ProtectedFromScaleIn)
	p.DataWeightedCapacity = nullableString(v.Data.WeightedCapacity)
	return w.q.PutInstance(w.ctx, p)
}
