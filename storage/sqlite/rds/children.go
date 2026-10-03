package rds

import (
	"maps"
	"slices"

	domain "stackd/storage/rds"
	"stackd/storage/sqlite/rds/internal/sqlcgen"
)

func (r reader) tags(k domain.Key) (map[string]string, error) {
	rows, e := r.q.ListTags(r.ctx, sqlcgen.ListTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make(map[string]string, len(rows))
	for _, v := range rows {
		out[v.TagKey] = v.TagValue
	}
	return out, nil
}

func (w writer) putTags(k domain.Key, values map[string]string) error {
	if e := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for _, name := range slices.Sorted(maps.Keys(values)) {
		if e := w.q.PutTag(w.ctx, sqlcgen.PutTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, TagKey: name, TagValue: values[name]}); e != nil {
			return e
		}
	}
	return nil
}

func (r reader) parameters(k domain.Key) (map[string]string, map[string]string, error) {
	rows, e := r.q.ListParameters(r.ctx, sqlcgen.ListParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, nil, e
	}
	values := make(map[string]string, len(rows))
	methods := make(map[string]string, len(rows))
	for _, v := range rows {

		values[v.ParameterName] = v.ParameterValue
		if v.ApplyMethod != "" {
			methods[v.ParameterName] = v.ApplyMethod
		}

	}
	return values, methods, nil
}

func (w writer) putParameters(k domain.Key, values, methods map[string]string) error {
	if e := w.q.DeleteParameters(w.ctx, sqlcgen.DeleteParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for _, name := range slices.Sorted(maps.Keys(values)) {
		if e := w.q.PutParameter(w.ctx, sqlcgen.PutParameterParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, ParameterName: name, ParameterValue: values[name], ApplyMethod: methods[name]}); e != nil {
			return e
		}
	}
	return nil
}

func (r reader) subnets(k domain.Key) ([]domain.Subnet, error) {
	rows, e := r.q.ListSubnets(r.ctx, sqlcgen.ListSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Subnet, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.Subnet{ID: v.SubnetID, VPCID: v.VpcID, AvailabilityZone: v.AvailabilityZone})
	}
	return out, nil
}

func (w writer) putSubnets(k domain.Key, values []domain.Subnet) error {
	if e := w.q.DeleteSubnets(w.ctx, sqlcgen.DeleteSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	for _, v := range values {
		if e := w.q.PutSubnet(w.ctx, sqlcgen.PutSubnetParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name, SubnetID: v.ID, VpcID: v.VPCID, AvailabilityZone: v.AvailabilityZone}); e != nil {
			return e
		}
	}
	return nil
}

func (w writer) deleteChildren(k domain.Key) error {
	if e := w.q.DeleteTags(w.ctx, sqlcgen.DeleteTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	if e := w.q.DeleteParameters(w.ctx, sqlcgen.DeleteParametersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name}); e != nil {
		return e
	}
	return w.q.DeleteSubnets(w.ctx, sqlcgen.DeleteSubnetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Kind: k.Kind, Name: k.Name})
}
