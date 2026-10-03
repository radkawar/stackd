package ecs

import (
	api "stackd/internal/awsapi/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

func (r reader) ServiceRevision(key domain.ServiceRevisionKey) (domain.ServiceRevisionRecord, error) {
	row, err := r.q.GetServiceRevision(r.ctx, sqlcgen.GetServiceRevisionParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		ClusterName: key.Name, ServiceName: key.ServiceName, RevisionID: key.ID,
	})
	if err != nil {
		return domain.ServiceRevisionRecord{}, missing(err)
	}
	out := domain.ServiceRevisionRecord{Key: key, Data: api.ServiceRevision{
		ServiceRevisionArn: new(api.String(key.ARN())), ServiceArn: new(api.String(key.ServiceKey.ARN())),
		ClusterArn: new(api.String(key.ClusterKey.ARN())), CreatedAt: timePointer(row.CreatedAt),
		TaskDefinition: stringPointer[api.String](row.TaskDefinition), LaunchType: stringPointer[api.LaunchType](row.LaunchType),
		PlatformFamily: stringPointer[api.String](row.PlatformFamily), PlatformVersion: stringPointer[api.String](row.PlatformVersion),
		GuardDutyEnabled: boolPointer[api.Boolean](row.GuardDutyEnabled),
	}}
	err = unmarshalFields(
		jsonReadField{row.CapacityProviderStrategy, &out.Data.CapacityProviderStrategy},
		jsonReadField{row.ContainerImages, &out.Data.ContainerImages},
		jsonReadField{row.EcsManagedResources, &out.Data.EcsManagedResources},
		jsonReadField{row.FargateEphemeralStorage, &out.Data.FargateEphemeralStorage},
		jsonReadField{row.LoadBalancers, &out.Data.LoadBalancers},
		jsonReadField{row.Monitoring, &out.Data.Monitoring},
		jsonReadField{row.NetworkConfiguration, &out.Data.NetworkConfiguration},
		jsonReadField{row.Overrides, &out.Data.Overrides},
		jsonReadField{row.ResolvedConfiguration, &out.Data.ResolvedConfiguration},
		jsonReadField{row.ServiceConnectConfiguration, &out.Data.ServiceConnectConfiguration},
		jsonReadField{row.ServiceRegistries, &out.Data.ServiceRegistries},
		jsonReadField{row.VolumeConfigurations, &out.Data.VolumeConfigurations},
		jsonReadField{row.VpcLatticeConfigurations, &out.Data.VpcLatticeConfigurations},
	)
	return out, err
}

func (w writer) PutServiceRevision(revision domain.ServiceRevisionRecord) error {
	key, data := revision.Key, revision.Data
	params := sqlcgen.PutServiceRevisionParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		ClusterName: key.Name, ServiceName: key.ServiceName, RevisionID: key.ID,
		CreatedAt: nullableTime(data.CreatedAt), TaskDefinition: nullableString(data.TaskDefinition),
		LaunchType: nullableString(data.LaunchType), PlatformFamily: nullableString(data.PlatformFamily),
		PlatformVersion: nullableString(data.PlatformVersion), GuardDutyEnabled: nullableBool(data.GuardDutyEnabled),
	}
	if err := marshalFields(
		jsonWriteField{&params.CapacityProviderStrategy, data.CapacityProviderStrategy},
		jsonWriteField{&params.ContainerImages, data.ContainerImages},
		jsonWriteField{&params.EcsManagedResources, data.EcsManagedResources},
		jsonWriteField{&params.FargateEphemeralStorage, data.FargateEphemeralStorage},
		jsonWriteField{&params.LoadBalancers, data.LoadBalancers},
		jsonWriteField{&params.Monitoring, data.Monitoring},
		jsonWriteField{&params.NetworkConfiguration, data.NetworkConfiguration},
		jsonWriteField{&params.Overrides, data.Overrides},
		jsonWriteField{&params.ResolvedConfiguration, data.ResolvedConfiguration},
		jsonWriteField{&params.ServiceConnectConfiguration, data.ServiceConnectConfiguration},
		jsonWriteField{&params.ServiceRegistries, data.ServiceRegistries},
		jsonWriteField{&params.VolumeConfigurations, data.VolumeConfigurations},
		jsonWriteField{&params.VpcLatticeConfigurations, data.VpcLatticeConfigurations},
	); err != nil {
		return err
	}
	return w.q.PutServiceRevision(w.ctx, params)
}

func (w writer) DeleteServiceRevisions(key domain.ServiceKey) error {
	return w.q.DeleteServiceRevisions(w.ctx, sqlcgen.DeleteServiceRevisionsParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region,
		ClusterName: key.Name, ServiceName: key.ServiceName,
	})
}
