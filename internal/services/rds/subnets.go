package rds

import (
	"context"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/rds"
)

func (s *Service) resolveSubnets(ctx context.Context, k Key, ids api.SubnetIdentifierList) ([]Subnet, string, error) {
	if s.networks == nil {
		return nil, "", unsupported("The EC2 networking owner is not configured.")
	}
	if len(ids) < 2 {
		return nil, "", failure("DBSubnetGroupDoesNotCoverEnoughAZs", "A subnet group must cover at least two Availability Zones.")
	}
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = string(id)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	subnets, e := s.networks.ResolveSubnets(ctx, k.ARN(), names)
	if e != nil {
		return nil, "", e
	}
	if len(subnets) != len(names) {
		return nil, "", failure("InvalidSubnet", "One or more subnets do not exist.")
	}
	vpc := ""
	zones := map[string]bool{}
	seen := map[string]bool{}
	for _, subnet := range subnets {

		if !slices.Contains(names, subnet.ID) || seen[subnet.ID] || subnet.VPCID == "" || subnet.AvailabilityZone == "" {
			return nil, "", failure("InvalidSubnet", "Invalid EC2 subnet selection.")
		}
		seen[subnet.ID] = true
		if vpc != "" && vpc != subnet.VPCID {
			return nil, "", failure("InvalidSubnet", "All subnets must belong to the same VPC.")
		}
		vpc = subnet.VPCID
		zones[subnet.AvailabilityZone] = true

	}
	if len(zones) < 2 {
		return nil, "", failure("DBSubnetGroupDoesNotCoverEnoughAZs", "A subnet group must cover at least two Availability Zones.")
	}
	slices.SortFunc(subnets, func(a, b Subnet) int {
		return strings.Compare(a.ID, b.ID)
	})
	return subnets, vpc, nil
}

func subnetGroupDTO(v SubnetGroup) api.DBSubnetGroup {
	out := api.DBSubnetGroup{DBSubnetGroupName: new(api.String(v.Key.Name)), DBSubnetGroupArn: new(api.String(v.Key.ARN())), DBSubnetGroupDescription: new(api.String(v.Description)), VpcId: new(api.String(v.VPCID)), SubnetGroupStatus: new(api.String("Complete")), Subnets: api.SubnetList{}}
	for _, subnet := range v.Subnets {
		out.Subnets = append(out.Subnets, api.Subnet{SubnetIdentifier: new(api.String(subnet.ID)), SubnetAvailabilityZone: &api.AvailabilityZone{Name: new(api.String(subnet.AvailabilityZone))}, SubnetStatus: new(api.String("Active"))})
	}
	return out
}

func (s *Service) createSubnetGroup(ctx context.Context, tx Transaction, in *api.CreateDBSubnetGroupMessage) (*api.CreateDBSubnetGroupResult, error) {
	k, e := resourceKey(ctx, "subgrp", value(in.DBSubnetGroupName))
	if e != nil {
		return nil, e
	}
	if strings.HasPrefix(k.Name, "default") {
		return nil, failure("InvalidParameterValue", "The subnet group name must not begin with default.")
	}
	description := value(in.DBSubnetGroupDescription)
	if description == "" || len(description) > 255 {
		return nil, failure("InvalidParameterValue", "A valid subnet group description is required.")
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "CreateDBSubnetGroup", k, nil, tags); e != nil {
		return nil, e
	}
	if _, e = tx.SubnetGroup(k); e == nil {
		return nil, existsError("subgrp")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	subnets, vpc, e := s.resolveSubnets(ctx, k, in.SubnetIds)
	if e != nil {
		return nil, e
	}
	v := SubnetGroup{Key: k, Description: description, VPCID: vpc, Subnets: subnets, Tags: tags}
	v.ResourceID, e = incarnation()
	if e != nil {
		return nil, e
	}
	v.Owner = cloudFormationClaim(ctx, k)
	if e = tx.PutSubnetGroup(v); e != nil {
		return nil, e
	}
	return &api.CreateDBSubnetGroupResult{DBSubnetGroup: new(subnetGroupDTO(v))}, nil
}

func (s *Service) loadSubnetGroup(ctx context.Context, tx Reader, action, name string) (SubnetGroup, error) {
	k, e := resourceKey(ctx, "subgrp", name)
	if e != nil {
		return SubnetGroup{}, e
	}
	v, e := tx.SubnetGroup(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound("subgrp")
	}
	if e != nil {
		return v, e
	}
	if e = checkCloudFormationOwner(ctx, k, v.Owner); e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}

func (s *Service) modifySubnetGroup(ctx context.Context, tx Transaction, in *api.ModifyDBSubnetGroupMessage) (*api.ModifyDBSubnetGroupResult, error) {
	v, e := s.loadSubnetGroup(ctx, tx, "ModifyDBSubnetGroup", value(in.DBSubnetGroupName))
	if e != nil {
		return nil, e
	}
	if in.DBSubnetGroupDescription != nil {

		d := string(*in.DBSubnetGroupDescription)
		if d == "" || len(d) > 255 {
			return nil, failure("InvalidParameterValue", "A valid subnet group description is required.")
		}
		v.Description = d

	}
	subnets, vpc, e := s.resolveSubnets(ctx, v.Key, in.SubnetIds)
	if e != nil {
		return nil, e
	}
	v.Subnets, v.VPCID = subnets, vpc
	if e = tx.PutSubnetGroup(v); e != nil {
		return nil, e
	}
	return &api.ModifyDBSubnetGroupResult{DBSubnetGroup: new(subnetGroupDTO(v))}, nil
}

func (s *Service) deleteSubnetGroup(ctx context.Context, tx Transaction, in *api.DeleteDBSubnetGroupMessage) (*emptyResult, error) {
	v, e := s.loadSubnetGroup(ctx, tx, "DeleteDBSubnetGroup", value(in.DBSubnetGroupName))
	if e != nil {
		return nil, e
	}
	return &emptyResult{}, tx.DeleteSubnetGroup(v.Key)
}

func (s *Service) describeSubnetGroups(ctx context.Context, tx Transaction, in *api.DescribeDBSubnetGroupsMessage) (*api.DBSubnetGroupMessage, error) {
	if len(in.Filters) > 0 {
		return nil, unsupported("Subnet group filters are not supported.")
	}
	start, limit, e := pageStart(ctx, "DescribeDBSubnetGroups", in.Marker, in.MaxRecords)
	if e != nil {
		return nil, e
	}
	name := ""
	if in.DBSubnetGroupName != nil {

		v, e := s.loadSubnetGroup(ctx, tx, "DescribeDBSubnetGroups", value(in.DBSubnetGroupName))
		if e != nil {
			return nil, e
		}
		name = v.Key.Name

	} else if e = s.authorize(ctx, "DescribeDBSubnetGroups", Key{}, nil, nil); e != nil {
		return nil, e
	}
	all, e := tx.SubnetGroups(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	out := &api.DBSubnetGroupMessage{DBSubnetGroups: api.DBSubnetGroups{}}
	last := ""
	for _, v := range all {

		if v.Key.Name <= start || name != "" && v.Key.Name != name {
			continue
		}
		if len(out.DBSubnetGroups) == limit {

			out.Marker = pageMarker(ctx, "DescribeDBSubnetGroups", last)
			break

		}
		out.DBSubnetGroups = append(out.DBSubnetGroups, subnetGroupDTO(v))
		last = v.Key.Name

	}
	return out, nil
}
