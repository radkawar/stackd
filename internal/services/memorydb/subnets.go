package memorydb

import (
	"context"
	"errors"
	"slices"
	api "stackd/internal/awsapi/memorydb"
	"strings"
)

func (s *Service) loadSubnetGroup(ctx context.Context, r Reader, action, name string) (SubnetGroup, error) {
	k, e := keyFor(ctx, "subnetgroup", name)
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
func subnetGroupDTO(v SubnetGroup) *api.SubnetGroup {
	out := &api.SubnetGroup{Name: new(api.String(v.Key.Name)), ARN: new(api.String(v.Key.ARN())), Description: new(api.String(v.Description)), VpcId: new(api.String(v.VPCID))}
	for _, subnet := range v.Subnets {
		out.Subnets = append(out.Subnets, api.Subnet{Identifier: new(api.String(subnet.ID)), AvailabilityZone: &api.AvailabilityZone{Name: new(api.String(subnet.AvailabilityZone))}})
	}
	return out
}
func (s *Service) resolveSubnets(ctx context.Context, k Key, in api.SubnetIdentifierList) ([]Subnet, string, error) {
	if len(in) == 0 {
		return nil, "", invalid("At least one subnet is required.")
	}
	if s.networks == nil {
		return nil, "", unsupported("Current EC2 subnet authority is not configured.")
	}
	ids := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		id := string(raw)
		if seen[id] {
			return nil, "", invalid("Duplicate subnet.")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	subnets, e := s.networks.ResolveSubnets(ctx, k.ARN(), ids)
	if e != nil {
		return nil, "", e
	}
	if len(subnets) != len(ids) {
		return nil, "", failure("SubnetNotAllowedFault", "One or more subnets do not exist in the current scope.")
	}
	vpc := ""
	for _, subnet := range subnets {
		if !seen[subnet.ID] || subnet.VPCID == "" || subnet.AvailabilityZone == "" {
			return nil, "", failure("InvalidSubnet", "Invalid subnet authority result.")
		}
		delete(seen, subnet.ID)
		if vpc != "" && vpc != subnet.VPCID {
			return nil, "", failure("InvalidSubnet", "All subnets must belong to one VPC.")
		}
		vpc = subnet.VPCID
	}
	slices.SortFunc(subnets, func(a, b Subnet) int { return strings.Compare(a.ID, b.ID) })
	return subnets, vpc, nil
}
func (s *Service) createSubnetGroup(ctx context.Context, tx Transaction, in *api.CreateSubnetGroupRequest) (*api.CreateSubnetGroupResponse, error) {
	k, e := keyFor(ctx, "subnetgroup", value(in.SubnetGroupName))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateSubnetGroup", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.SubnetGroup(k); e == nil {
		return nil, exists(k.Kind)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	subnets, vpc, e := s.resolveSubnets(ctx, k, in.SubnetIds)
	if e != nil {
		return nil, e
	}
	v := SubnetGroup{Key: k, Description: value(in.Description), VPCID: vpc, Subnets: subnets, Tags: tags}
	if e = tx.PutSubnetGroup(v); e != nil {
		return nil, e
	}
	return &api.CreateSubnetGroupResponse{SubnetGroup: subnetGroupDTO(v)}, nil
}
func (s *Service) updateSubnetGroup(ctx context.Context, tx Transaction, in *api.UpdateSubnetGroupRequest) (*api.UpdateSubnetGroupResponse, error) {
	v, e := s.loadSubnetGroup(ctx, tx, "UpdateSubnetGroup", value(in.SubnetGroupName))
	if e != nil {
		return nil, e
	}
	if in.Description != nil {
		v.Description = value(in.Description)
	}
	if in.SubnetIds != nil {
		v.Subnets, v.VPCID, e = s.resolveSubnets(ctx, v.Key, in.SubnetIds)
		if e != nil {
			return nil, e
		}
	}
	if e = tx.PutSubnetGroup(v); e != nil {
		return nil, e
	}
	return &api.UpdateSubnetGroupResponse{SubnetGroup: subnetGroupDTO(v)}, nil
}
func (s *Service) deleteSubnetGroup(ctx context.Context, tx Transaction, in *api.DeleteSubnetGroupRequest) (*api.DeleteSubnetGroupResponse, error) {
	v, e := s.loadSubnetGroup(ctx, tx, "DeleteSubnetGroup", value(in.SubnetGroupName))
	if e != nil {
		return nil, e
	}
	if e = tx.DeleteSubnetGroup(v.Key); e != nil {
		return nil, e
	}
	return &api.DeleteSubnetGroupResponse{SubnetGroup: subnetGroupDTO(v)}, nil
}
func (s *Service) describeSubnetGroups(ctx context.Context, tx Transaction, in *api.DescribeSubnetGroupsRequest) (*api.DescribeSubnetGroupsResponse, error) {
	var rows []SubnetGroup
	if in.SubnetGroupName != nil {
		v, e := s.loadSubnetGroup(ctx, tx, "DescribeSubnetGroups", value(in.SubnetGroupName))
		if e != nil {
			return nil, e
		}
		rows = []SubnetGroup{v}
	} else {
		if e := s.authorize(ctx, "DescribeSubnetGroups", Key{}, nil, nil); e != nil {
			return nil, e
		}
		var e error
		rows, e = tx.SubnetGroups(scopeFor(ctx))
		if e != nil {
			return nil, e
		}
	}
	rows, next, e := page(rows, in.MaxResults, in.NextToken, binding(ctx, "DescribeSubnetGroups", value(in.SubnetGroupName)), func(v SubnetGroup) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.DescribeSubnetGroupsResponse{NextToken: next}
	for _, v := range rows {
		out.SubnetGroups = append(out.SubnetGroups, *subnetGroupDTO(v))
	}
	return out, nil
}
