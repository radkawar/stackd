package elasticache

import (
	"context"
	"errors"
	"slices"
	api "stackd/internal/awsapi/elasticache"
)

func subnetOutput(v SubnetGroup) *api.CacheSubnetGroup {
	out := &api.CacheSubnetGroup{ARN: new(api.String(v.Key.ARN())), CacheSubnetGroupName: new(api.String(v.Key.Name)), CacheSubnetGroupDescription: new(api.String(v.Description)), VpcId: new(api.String(v.VPCID))}
	for _, sub := range v.Subnets {
		out.Subnets = append(out.Subnets, api.Subnet{SubnetIdentifier: new(api.String(sub.ID)), SubnetAvailabilityZone: &api.AvailabilityZone{Name: new(api.String(sub.AvailabilityZone))}})
	}
	return out
}
func (s *Service) loadSubnetGroup(ctx context.Context, r Reader, action, name string) (SubnetGroup, error) {
	k, e := resourceKey(ctx, "subnetgroup", name)
	if e != nil {
		return SubnetGroup{}, e
	}
	v, e := r.SubnetGroup(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(k.Kind)
	}
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func (s *Service) resolveSubnets(ctx context.Context, k Key, ids api.SubnetIdentifierList) ([]Subnet, string, error) {
	if s.networks == nil {
		return nil, "", unsupported("Subnet groups require the current EC2 network authority.")
	}
	if len(ids) == 0 {
		return nil, "", failure("InvalidParameterValue", "SubnetIds must not be empty.")
	}
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		if slices.Contains(values, string(id)) {
			return nil, "", failure("InvalidParameterValue", "Subnet IDs must be unique.")
		}
		values = append(values, string(id))
	}
	subnets, e := s.networks.ResolveSubnets(ctx, k.ARN(), values)
	if e != nil {
		return nil, "", e
	}
	if len(subnets) != len(ids) {
		return nil, "", failure("InvalidSubnet", "One or more subnets do not exist.")
	}
	vpc := ""
	found := map[string]bool{}
	for _, sub := range subnets {
		if !slices.Contains(values, sub.ID) || found[sub.ID] || sub.VPCID == "" || sub.AvailabilityZone == "" {
			return nil, "", failure("InvalidSubnet", "The subnet authority returned an invalid subnet.")
		}
		if vpc != "" && vpc != sub.VPCID {
			return nil, "", failure("InvalidSubnet", "Subnets must belong to the same VPC.")
		}
		vpc = sub.VPCID
		found[sub.ID] = true
	}
	slices.SortFunc(subnets, func(a, b Subnet) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return subnets, vpc, nil
}
func (s *Service) createSubnetGroup(ctx context.Context, tx Transaction, in *api.CreateCacheSubnetGroupMessage) (*api.CreateCacheSubnetGroupResult, error) {
	k, e := resourceKey(ctx, "subnetgroup", value(in.CacheSubnetGroupName))
	if e != nil {
		return nil, e
	}
	if value(in.CacheSubnetGroupDescription) == "" {
		return nil, failure("InvalidParameterValue", "Description is required.")
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateCacheSubnetGroup", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.SubnetGroup(k); e == nil {
		return nil, existsError(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	subnets, vpc, e := s.resolveSubnets(ctx, k, in.SubnetIds)
	if e != nil {
		return nil, e
	}
	v := SubnetGroup{Key: k, Description: value(in.CacheSubnetGroupDescription), VPCID: vpc, Subnets: subnets, Tags: tags}
	return &api.CreateCacheSubnetGroupResult{CacheSubnetGroup: subnetOutput(v)}, tx.PutSubnetGroup(v)
}
func (s *Service) modifySubnetGroup(ctx context.Context, tx Transaction, in *api.ModifyCacheSubnetGroupMessage) (*api.ModifyCacheSubnetGroupResult, error) {
	v, e := s.loadSubnetGroup(ctx, tx, "ModifyCacheSubnetGroup", value(in.CacheSubnetGroupName))
	if e != nil {
		return nil, e
	}
	if in.CacheSubnetGroupDescription != nil {
		if value(in.CacheSubnetGroupDescription) == "" {
			return nil, failure("InvalidParameterValue", "Description must not be empty.")
		}
		v.Description = value(in.CacheSubnetGroupDescription)
	}
	ids := in.SubnetIds
	if ids == nil {
		for _, sub := range v.Subnets {
			ids = append(ids, api.String(sub.ID))
		}
	}
	v.Subnets, v.VPCID, e = s.resolveSubnets(ctx, v.Key, ids)
	if e != nil {
		return nil, e
	}
	return &api.ModifyCacheSubnetGroupResult{CacheSubnetGroup: subnetOutput(v)}, tx.PutSubnetGroup(v)
}
func (s *Service) deleteSubnetGroup(ctx context.Context, tx Transaction, in *api.DeleteCacheSubnetGroupMessage) (*struct{}, error) {
	v, e := s.loadSubnetGroup(ctx, tx, "DeleteCacheSubnetGroup", value(in.CacheSubnetGroupName))
	if e != nil {
		return nil, e
	}
	return &struct{}{}, tx.DeleteSubnetGroup(v.Key)
}
func (s *Service) describeSubnetGroups(ctx context.Context, tx Transaction, in *api.DescribeCacheSubnetGroupsMessage) (*api.CacheSubnetGroupMessage, error) {
	var all []SubnetGroup
	var e error
	if in.CacheSubnetGroupName != nil {
		v, err := s.loadSubnetGroup(ctx, tx, "DescribeCacheSubnetGroups", value(in.CacheSubnetGroupName))
		e = err
		all = []SubnetGroup{v}
	} else {
		e = s.authorize(ctx, "DescribeCacheSubnetGroups", Key{}, nil, nil)
		if e == nil {
			all, e = tx.SubnetGroups(scopeFor(ctx))
		}
	}
	if e != nil {
		return nil, e
	}
	selected, next, e := page(ctx, "DescribeCacheSubnetGroups", value(in.CacheSubnetGroupName), all, in.Marker, in.MaxRecords, func(v SubnetGroup) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.CacheSubnetGroupMessage{Marker: next}
	for _, v := range selected {
		out.CacheSubnetGroups = append(out.CacheSubnetGroups, *subnetOutput(v))
	}
	return out, nil
}
