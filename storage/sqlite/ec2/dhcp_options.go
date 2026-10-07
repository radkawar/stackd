package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) DHCPDefaults(scope domain.Scope) (domain.DHCPDefaultsRecord, error) {
	row, err := r.q.GetDhcpDefaults(r.ctx, sqlcgen.GetDhcpDefaultsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return domain.DHCPDefaultsRecord{}, missing(err)
	}
	return domain.DHCPDefaultsRecord{Scope: scope, OptionsID: row.OptionsID}, nil
}

func (w writer) PutDHCPDefaults(v domain.DHCPDefaultsRecord) error {
	return w.q.PutDhcpDefaults(w.ctx, sqlcgen.PutDhcpDefaultsParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, OptionsID: v.OptionsID})
}

func (r reader) DHCPOptions(k domain.ResourceKey) (domain.DHCPOptionsRecord, error) {
	row, err := r.q.GetDhcpOptions(r.ctx, sqlcgen.GetDhcpOptionsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.DHCPOptionsRecord{}, missing(err)
	}
	return r.dhcpOptions(row)
}

func (r reader) DHCPOptionsSets(scope domain.Scope) ([]domain.DHCPOptionsRecord, error) {
	rows, err := r.q.ListDhcpOptions(r.ctx, sqlcgen.ListDhcpOptionsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.DHCPOptionsRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.dhcpOptions(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) dhcpOptions(row sqlcgen.Ec2DhcpOption) (domain.DHCPOptionsRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.DHCPOptionsRecord{Key: k, Data: api.DhcpOptions{DhcpOptionsId: stringPointer[api.String](row.DhcpOptionsID), OwnerId: stringPointer[api.String](row.OwnerID)}}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	if row.TagsPresent {
		tags, err := r.q.ListDhcpOptionsTags(r.ctx, sqlcgen.ListDhcpOptionsTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		out.Data.Tags = make(api.TagList, len(tags))
		for i, tag := range tags {
			out.Data.Tags[i] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
		}
	}
	if row.ConfigurationsPresent {
		configs, err := r.q.ListDhcpConfigurations(r.ctx, sqlcgen.ListDhcpConfigurationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return out, err
		}
		out.Data.DhcpConfigurations = make(api.DhcpConfigurationList, len(configs))
		for i, config := range configs {
			out.Data.DhcpConfigurations[i].Key = stringPointer[api.String](config.Key)
			if config.ValuesPresent {
				values, err := r.q.ListDhcpConfigurationValues(r.ctx, sqlcgen.ListDhcpConfigurationValuesParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, ConfigurationPosition: config.Position})
				if err != nil {
					return out, err
				}
				out.Data.DhcpConfigurations[i].Values = make(api.DhcpConfigurationValueList, len(values))
				for j, value := range values {
					out.Data.DhcpConfigurations[i].Values[j].Value = stringPointer[api.String](value.Value)
				}
			}
		}
	}
	return out, nil
}

func (w writer) PutDHCPOptions(v domain.DHCPOptionsRecord) error {
	k, d := v.Key, &v.Data
	if err := w.q.PutDhcpOptions(w.ctx, sqlcgen.PutDhcpOptionsParams{
		Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID,
		DhcpOptionsID: nullableString(d.DhcpOptionsId), OwnerID: nullableString(d.OwnerId), TagsPresent: d.Tags != nil, ConfigurationsPresent: d.DhcpConfigurations != nil,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteDhcpOptionsTags(w.ctx, sqlcgen.DeleteDhcpOptionsTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, tag := range d.Tags {
		if err := w.q.PutDhcpOptionsTag(w.ctx, sqlcgen.PutDhcpOptionsTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteDhcpConfigurations(w.ctx, sqlcgen.DeleteDhcpConfigurationsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, config := range d.DhcpConfigurations {
		if err := w.q.PutDhcpConfiguration(w.ctx, sqlcgen.PutDhcpConfigurationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(config.Key), ValuesPresent: config.Values != nil}); err != nil {
			return err
		}
		for j, value := range config.Values {
			if err := w.q.PutDhcpConfigurationValue(w.ctx, sqlcgen.PutDhcpConfigurationValueParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, ConfigurationPosition: int64(i), Position: int64(j), Value: nullableString(value.Value)}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) DeleteDHCPOptions(k domain.ResourceKey) error {
	return deleted(w.q.DeleteDhcpOptions(w.ctx, sqlcgen.DeleteDhcpOptionsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
