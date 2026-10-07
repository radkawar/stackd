package ecs

import (
	api "stackd/internal/awsapi/ecs"
	domain "stackd/storage/ecs"
	"stackd/storage/sqlite/ecs/internal/sqlcgen"
)

func (r reader) Cluster(k domain.ClusterKey) (domain.ClusterRecord, error) {
	row, err := r.q.GetCluster(r.ctx, sqlcgen.GetClusterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.ClusterRecord{}, missing(err)
	}
	return r.cluster(row)
}
func (r reader) Clusters(q domain.ClusterQuery) ([]domain.ClusterRecord, error) {
	rows, err := r.q.ListClusters(r.ctx, sqlcgen.ListClustersParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, AfterName: q.After, IncludeInactive: flag(q.IncludeInactive), RowLimit: rowLimit(q.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ClusterRecord, 0, len(rows))
	for _, row := range rows {
		record, err := r.cluster(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (r reader) ActiveClusterKeys(partition, accountID string) ([]domain.ClusterKey, error) {
	rows, err := r.q.ListActiveClusterKeys(r.ctx, sqlcgen.ListActiveClusterKeysParams{Partition: partition, AccountID: accountID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ClusterKey, len(rows))
	for i, row := range rows {
		out[i] = domain.ClusterKey{Scope: domain.Scope{Partition: partition, AccountID: accountID, Region: row.Region}, Name: row.Name}
	}
	return out, nil
}
func (r reader) cluster(row sqlcgen.EcsCluster) (domain.ClusterRecord, error) {
	k := domain.ClusterKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}
	out := domain.ClusterRecord{Ownership: row.Ownership, Key: k, Created: row.Created, Updated: row.Updated, Data: api.Cluster{
		ClusterArn: stringPointer[api.String](row.ClusterArn), ClusterName: stringPointer[api.String](row.ClusterName), Status: stringPointer[api.String](row.Status),
		ActiveServicesCount: integerPointer[api.Integer](row.ActiveServicesCount), PendingTasksCount: integerPointer[api.Integer](row.PendingTasksCount),
		RegisteredContainerInstancesCount: integerPointer[api.Integer](row.RegisteredContainerInstancesCount), RunningTasksCount: integerPointer[api.Integer](row.RunningTasksCount),
		AttachmentsStatus: stringPointer[api.String](row.AttachmentsStatus),
	}}
	d := &out.Data
	if err := unmarshalFields(
		jsonReadField{row.Attachments, &d.Attachments}, jsonReadField{row.Configuration, &d.Configuration},
		jsonReadField{row.DefaultCapacityProviderStrategy, &d.DefaultCapacityProviderStrategy},
		jsonReadField{row.ServiceConnectDefaults, &d.ServiceConnectDefaults}, jsonReadField{row.Settings, &d.Settings}, jsonReadField{row.Statistics, &d.Statistics},
	); err != nil {
		return out, err
	}
	if row.CapacityProvidersPresent {
		values, err := r.q.ListClusterCapacityProviders(r.ctx, sqlcgen.ListClusterCapacityProvidersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Original: false})
		if err != nil {
			return out, err
		}
		d.CapacityProviders = make(api.StringList, len(values))
		for i, value := range values {
			d.CapacityProviders[i] = api.String(value)
		}
	}
	original, err := r.q.GetClusterCreateInput(r.ctx, sqlcgen.GetClusterCreateInputParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return out, err
	}
	in := &out.CreateInput
	in.ClusterName = stringPointer[api.String](original.ClusterName)
	if err := unmarshalFields(
		jsonReadField{original.Configuration, &in.Configuration}, jsonReadField{original.DefaultCapacityProviderStrategy, &in.DefaultCapacityProviderStrategy},
		jsonReadField{original.ServiceConnectDefaults, &in.ServiceConnectDefaults}, jsonReadField{original.Settings, &in.Settings},
	); err != nil {
		return out, err
	}
	if original.CapacityProvidersPresent {
		values, err := r.q.ListClusterCapacityProviders(r.ctx, sqlcgen.ListClusterCapacityProvidersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Original: true})
		if err != nil {
			return out, err
		}
		in.CapacityProviders = make(api.StringList, len(values))
		for i, value := range values {
			in.CapacityProviders[i] = api.String(value)
		}
	}
	if original.TagsPresent {
		tags, err := r.q.ListClusterCreateTags(r.ctx, sqlcgen.ListClusterCreateTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
		if err != nil {
			return out, err
		}
		in.Tags = make(api.Tags, len(tags))
		for i, tag := range tags {
			in.Tags[i] = api.Tag{Key: stringPointer[api.TagKey](tag.Key), Value: stringPointer[api.TagValue](tag.Value)}
		}
	}
	return out, nil
}
func (w writer) PutCluster(v domain.ClusterRecord) error {
	k, d, in := v.Key, &v.Data, &v.CreateInput
	params := sqlcgen.PutClusterParams{Ownership: v.Ownership, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		ClusterArn: nullableString(d.ClusterArn), ClusterName: nullableString(d.ClusterName), Status: nullableString(d.Status),
		ActiveServicesCount: nullableInteger(d.ActiveServicesCount), PendingTasksCount: nullableInteger(d.PendingTasksCount),
		RegisteredContainerInstancesCount: nullableInteger(d.RegisteredContainerInstancesCount), RunningTasksCount: nullableInteger(d.RunningTasksCount),
		AttachmentsStatus: nullableString(d.AttachmentsStatus), CapacityProvidersPresent: d.CapacityProviders != nil, Created: v.Created, Updated: v.Updated}
	if err := marshalFields(
		jsonWriteField{&params.Attachments, d.Attachments}, jsonWriteField{&params.Configuration, d.Configuration},
		jsonWriteField{&params.DefaultCapacityProviderStrategy, d.DefaultCapacityProviderStrategy},
		jsonWriteField{&params.ServiceConnectDefaults, d.ServiceConnectDefaults}, jsonWriteField{&params.Settings, d.Settings}, jsonWriteField{&params.Statistics, d.Statistics},
	); err != nil {
		return err
	}
	original := sqlcgen.PutClusterCreateInputParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		ClusterName: nullableString(in.ClusterName), CapacityProvidersPresent: in.CapacityProviders != nil, TagsPresent: in.Tags != nil,
	}
	if err := marshalFields(
		jsonWriteField{&original.Configuration, in.Configuration}, jsonWriteField{&original.DefaultCapacityProviderStrategy, in.DefaultCapacityProviderStrategy},
		jsonWriteField{&original.ServiceConnectDefaults, in.ServiceConnectDefaults}, jsonWriteField{&original.Settings, in.Settings},
	); err != nil {
		return err
	}
	if err := w.q.PutCluster(w.ctx, params); err != nil {
		return err
	}
	if err := w.q.PutClusterCreateInput(w.ctx, original); err != nil {
		return err
	}
	if err := w.q.DeleteClusterCapacityProviders(w.ctx, sqlcgen.DeleteClusterCapacityProvidersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for _, providers := range []struct {
		original bool
		values   api.StringList
	}{{false, d.CapacityProviders}, {true, in.CapacityProviders}} {
		for i, provider := range providers.values {
			if err := w.q.PutClusterCapacityProvider(w.ctx, sqlcgen.PutClusterCapacityProviderParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Original: providers.original, Position: int64(i), Provider: string(provider)}); err != nil {
				return err
			}
		}
	}
	if err := w.q.DeleteClusterCreateTags(w.ctx, sqlcgen.DeleteClusterCreateTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name}); err != nil {
		return err
	}
	for i, tag := range in.Tags {
		if err := w.q.PutClusterCreateTag(w.ctx, sqlcgen.PutClusterCreateTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}
