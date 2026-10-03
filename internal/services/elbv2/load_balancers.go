package elbv2

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	api "stackd/internal/awsapi/elbv2"
	"strconv"
	"time"
)

func registerLoadBalancers(s *Service) {
	register(s, "CreateLoadBalancer", s.createLoadBalancer)
	register(s, "DeleteLoadBalancer", s.deleteLoadBalancer)
	register(s, "DescribeLoadBalancers", s.describeLoadBalancers)
	register(s, "SetSubnets", s.setSubnets)
	register(s, "SetSecurityGroups", s.setSecurityGroups)
	register(s, "SetIpAddressType", s.setIPAddressType)
	register(s, "DescribeLoadBalancerAttributes", s.describeLoadBalancerAttributes)
	register(s, "ModifyLoadBalancerAttributes", s.modifyLoadBalancerAttributes)
}
func subnetIDs(subnets api.Subnets, mappings api.SubnetMappings) ([]string, error) {
	if len(subnets) > 0 && len(mappings) > 0 {
		return nil, invalid("Specify Subnets or SubnetMappings, not both")
	}
	out := plainList(subnets)
	for _, m := range mappings {
		if m.AllocationId != nil || m.IPv6Address != nil || m.PrivateIPv4Address != nil || m.SourceNatIpv6Prefix != nil {
			return nil, unsupported("Application load balancers do not support explicit subnet addresses")
		}
		out = append(out, value(m.SubnetId))
	}
	if len(out) < 2 {
		return nil, invalid("At least two subnets in distinct Availability Zones are required")
	}
	slices.Sort(out)
	if len(slices.Compact(slices.Clone(out))) != len(out) {
		return nil, invalid("Duplicate subnet")
	}
	return out, nil
}
func (s *Service) createLoadBalancer(ctx context.Context, tx Transaction, in *api.CreateLoadBalancerInput) (*api.CreateLoadBalancerOutput, error) {
	sc := scopeFor(ctx)
	name := value(in.Name)
	if e := validateName(name, true); e != nil {
		return nil, e
	}
	typ := value(in.Type)
	if typ == "" {
		typ = "application"
	}
	if typ != "application" {
		return nil, unsupported("Network and Gateway Load Balancers are not supported")
	}
	ip := value(in.IpAddressType)
	if ip == "" {
		ip = "ipv4"
	}
	if ip != "ipv4" {
		return nil, unsupported("IPv6 load balancers are not supported")
	}
	scheme := value(in.Scheme)
	if scheme == "" {
		scheme = "internet-facing"
	}
	if scheme != "internal" && scheme != "internet-facing" {
		return nil, failure("InvalidScheme", "Scheme must be internal or internet-facing")
	}
	if in.CustomerOwnedIpv4Pool != nil || in.IpamPools != nil || in.EnablePrefixForIpv6SourceNat != nil {
		return nil, unsupported("Outposts, IPAM and IPv6 source NAT are not supported")
	}
	subnets, e := subnetIDs(in.Subnets, in.SubnetMappings)
	if e != nil {
		return nil, e
	}
	groups := plainList(in.SecurityGroups)
	vpc, zones, e := s.validateLoadBalancerNetwork(ctx, subnets, groups)
	if e != nil {
		return nil, e
	}
	if len(groups) == 0 {
		groups, e = s.networks.DefaultSecurityGroups(ctx, sc, vpc)
		if e != nil {
			return nil, e
		}
	}
	slices.Sort(groups)
	conditions := map[string][]string{"elasticloadbalancing:Scheme": {scheme}, "elasticloadbalancing:Subnet": subnets, "elasticloadbalancing:SecurityGroup": groups}
	if e = s.authorizeCreate(ctx, "CreateLoadBalancer", arn(sc, "loadbalancer/app/"+name+"/*"), in.Tags, conditions); e != nil {
		return nil, e
	}
	rows, e := tx.LoadBalancers(sc)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if value(v.Data.LoadBalancerName) != name {
			continue
		}
		if v.Deleting {
			return nil, failure("DuplicateLoadBalancerName", "Load balancer deletion is in progress")
		}
		existing := []string{}
		for _, z := range v.Data.AvailabilityZones {
			existing = append(existing, value(z.SubnetId))
		}
		slices.Sort(existing)
		sg := plainList(v.Data.SecurityGroups)
		slices.Sort(sg)
		if value(v.Data.Scheme) != scheme || value(v.Data.IpAddressType) != ip || !reflect.DeepEqual(existing, subnets) || !reflect.DeepEqual(sg, groups) {
			return nil, failure("DuplicateLoadBalancerName", "A load balancer with the same name has different settings")
		}
		return &api.CreateLoadBalancerOutput{LoadBalancers: api.LoadBalancers{v.Data}}, nil
	}
	id, e := tx.NextID()
	if e != nil {
		return nil, e
	}
	d := api.LoadBalancer{LoadBalancerName: in.Name, AvailabilityZones: zones, SecurityGroups: in.SecurityGroups, State: &api.LoadBalancerState{}}
	text(&d.LoadBalancerArn, arn(sc, fmt.Sprintf("loadbalancer/app/%s/%016x", name, id)))
	text(&d.Type, typ)
	text(&d.Scheme, scheme)
	text(&d.IpAddressType, ip)
	text(&d.VpcId, vpc)
	text(&d.State.Code, "provisioning")
	now := api.CreatedTime(s.clock.Now())
	d.CreatedTime = &now
	d.SecurityGroups = make(api.SecurityGroups, len(groups))
	for i, g := range groups {
		d.SecurityGroups[i] = api.SecurityGroupId(g)
	}
	v := LoadBalancerRecord{Scope: sc, Data: d, Tags: in.Tags, IdleTimeout: 60 * time.Second, AttachmentIDs: map[string]string{}, AttachmentGenerations: map[string]uint64{}, NextReconcile: s.clock.Now(), Version: 1}
	if e = assignAttachmentGenerations(tx, &v, zones); e != nil {
		return nil, e
	}
	// Reserve the primary frontend address with the ALB record. EC2 allocation
	// is transactional control-plane state; native listeners start after commit.
	primary := value(zones[0].SubnetId)
	attachment, e := s.networks.Allocate(tx.Context(), sc, value(d.LoadBalancerArn), primary, v.AttachmentGenerations[primary], scheme == "internet-facing", groups)
	if e != nil {
		return nil, networkAdmissionError(e)
	}
	v.AttachmentIDs[primary] = attachment.ID
	ensureDNSName(&v)
	if e = tx.PutLoadBalancer(v); e != nil {
		return nil, e
	}
	return &api.CreateLoadBalancerOutput{LoadBalancers: api.LoadBalancers{v.Data}}, nil
}
func (s *Service) deleteLoadBalancer(ctx context.Context, tx Transaction, in *api.DeleteLoadBalancerInput) (*api.DeleteLoadBalancerOutput, error) {
	sc := scopeFor(ctx)
	a := value(in.LoadBalancerArn)
	if e := scopedARN(sc, a, "loadbalancer"); e != nil {
		return nil, e
	}
	v, e := tx.LoadBalancer(sc, a)
	if e == ErrNotFound {
		if e = s.authorize(ctx, "DeleteLoadBalancer", a, nil, nil); e != nil {
			return nil, e
		}
		return &api.DeleteLoadBalancerOutput{}, nil
	}
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "DeleteLoadBalancer", a, v.Tags, nil); e != nil {
		return nil, e
	}
	if v.DeletionProtection {
		return nil, failure("OperationNotPermitted", "Load balancer deletion protection is enabled")
	}
	v.Deleting = true
	v.Version++
	v.NextReconcile = s.clock.Now()
	if e = tx.PutLoadBalancer(v); e != nil {
		return nil, e
	}
	ls, e := tx.Listeners(sc)
	if e != nil {
		return nil, e
	}
	for _, l := range ls {
		if value(l.Data.LoadBalancerArn) == a {
			if e = deleteListenerRows(tx, l); e != nil {
				return nil, e
			}
		}
	}
	if e = refreshAssociations(tx, sc); e != nil {
		return nil, e
	}
	return &api.DeleteLoadBalancerOutput{}, nil
}
func (s *Service) describeLoadBalancers(ctx context.Context, tx Transaction, in *api.DescribeLoadBalancersInput) (*api.DescribeLoadBalancersOutput, error) {
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, "DescribeLoadBalancers", "*", nil, nil); e != nil {
		return nil, e
	}
	if len(in.LoadBalancerArns) > 0 && len(in.Names) > 0 {
		return nil, invalid("Specify names or ARNs, not both")
	}
	rows, e := tx.LoadBalancers(sc)
	if e != nil {
		return nil, e
	}
	out := api.LoadBalancers{}
	found := map[string]bool{}
	for _, v := range rows {
		if v.Deleting {
			continue
		}
		a, n := value(v.Data.LoadBalancerArn), value(v.Data.LoadBalancerName)
		if len(in.LoadBalancerArns) > 0 && !slices.Contains(in.LoadBalancerArns, api.LoadBalancerArn(a)) {
			continue
		}
		if len(in.Names) > 0 && !slices.Contains(in.Names, api.LoadBalancerName(n)) {
			continue
		}
		out = append(out, v.Data)
		found[a] = true
		found[n] = true
	}
	for _, a := range in.LoadBalancerArns {
		if !found[string(a)] {
			return nil, failure("LoadBalancerNotFound", "Load balancer does not exist")
		}
	}
	for _, n := range in.Names {
		if !found[string(n)] {
			return nil, failure("LoadBalancerNotFound", "Load balancer does not exist")
		}
	}
	out, next, e := page(out, in.Marker, in.PageSize, fmt.Sprint("DescribeLoadBalancers:", sc, in.LoadBalancerArns, in.Names), func(v api.LoadBalancer) string { return value(v.LoadBalancerArn) })
	return &api.DescribeLoadBalancersOutput{LoadBalancers: out, NextMarker: next}, e
}
func (s *Service) setSubnets(ctx context.Context, tx Transaction, in *api.SetSubnetsInput) (*api.SetSubnetsOutput, error) {
	v, e := loadBalancer(tx, scopeFor(ctx), value(in.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	subnets, e := subnetIDs(in.Subnets, in.SubnetMappings)
	if e != nil {
		return nil, e
	}
	if in.EnablePrefixForIpv6SourceNat != nil || (in.IpAddressType != nil && value(in.IpAddressType) != "ipv4") {
		return nil, unsupported("IPv6 is not supported")
	}
	if e = s.authorize(ctx, "SetSubnets", value(in.LoadBalancerArn), v.Tags, map[string][]string{"elasticloadbalancing:Subnet": subnets}); e != nil {
		return nil, e
	}
	vpc, zones, e := s.validateLoadBalancerNetwork(ctx, subnets, plainList(v.Data.SecurityGroups))
	if e != nil {
		return nil, e
	}
	if vpc != value(v.Data.VpcId) {
		return nil, failure("InvalidConfigurationRequest", "Cannot change the load balancer VPC")
	}
	if e = assignAttachmentGenerations(tx, &v, zones); e != nil {
		return nil, e
	}
	v.Data.AvailabilityZones = zones
	v.Version++
	v.NextReconcile = s.clock.Now()
	if e = tx.PutLoadBalancer(v); e != nil {
		return nil, e
	}
	return &api.SetSubnetsOutput{AvailabilityZones: zones, IpAddressType: v.Data.IpAddressType}, nil
}
func (s *Service) setSecurityGroups(ctx context.Context, tx Transaction, in *api.SetSecurityGroupsInput) (*api.SetSecurityGroupsOutput, error) {
	v, e := loadBalancer(tx, scopeFor(ctx), value(in.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	if in.EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic != nil {
		return nil, unsupported("PrivateLink is not supported")
	}
	if len(in.SecurityGroups) == 0 {
		return nil, invalid("At least one security group is required")
	}
	if e = s.authorize(ctx, "SetSecurityGroups", value(in.LoadBalancerArn), v.Tags, map[string][]string{"elasticloadbalancing:SecurityGroup": plainList(in.SecurityGroups)}); e != nil {
		return nil, e
	}
	subnets := []string{}
	for _, z := range v.Data.AvailabilityZones {
		subnets = append(subnets, value(z.SubnetId))
	}
	if _, _, e = s.validateLoadBalancerNetwork(ctx, subnets, plainList(in.SecurityGroups)); e != nil {
		return nil, e
	}
	v.Data.SecurityGroups = in.SecurityGroups
	v.Version++
	v.NextReconcile = s.clock.Now()
	if e = tx.PutLoadBalancer(v); e != nil {
		return nil, e
	}
	return &api.SetSecurityGroupsOutput{SecurityGroupIds: in.SecurityGroups}, nil
}
func (s *Service) setIPAddressType(ctx context.Context, tx Transaction, in *api.SetIpAddressTypeInput) (*api.SetIpAddressTypeOutput, error) {
	v, e := loadBalancer(tx, scopeFor(ctx), value(in.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "SetIpAddressType", value(in.LoadBalancerArn), v.Tags, nil); e != nil {
		return nil, e
	}
	if value(in.IpAddressType) != "ipv4" {
		return nil, unsupported("IPv6 is not supported")
	}
	return &api.SetIpAddressTypeOutput{IpAddressType: v.Data.IpAddressType}, nil
}
func loadBalancerAttributes(v LoadBalancerRecord) api.LoadBalancerAttributes {
	out := api.LoadBalancerAttributes{}
	for _, kv := range [][2]string{{"deletion_protection.enabled", strconv.FormatBool(v.DeletionProtection)}, {"idle_timeout.timeout_seconds", strconv.FormatInt(int64(v.IdleTimeout/time.Second), 10)}} {
		var a api.LoadBalancerAttribute
		text(&a.Key, kv[0])
		text(&a.Value, kv[1])
		out = append(out, a)
	}
	return out
}
func (s *Service) describeLoadBalancerAttributes(ctx context.Context, tx Transaction, in *api.DescribeLoadBalancerAttributesInput) (*api.DescribeLoadBalancerAttributesOutput, error) {
	if e := s.authorize(ctx, "DescribeLoadBalancerAttributes", "*", nil, nil); e != nil {
		return nil, e
	}
	v, e := loadBalancer(tx, scopeFor(ctx), value(in.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	return &api.DescribeLoadBalancerAttributesOutput{Attributes: loadBalancerAttributes(v)}, nil
}
func (s *Service) modifyLoadBalancerAttributes(ctx context.Context, tx Transaction, in *api.ModifyLoadBalancerAttributesInput) (*api.ModifyLoadBalancerAttributesOutput, error) {
	v, e := loadBalancer(tx, scopeFor(ctx), value(in.LoadBalancerArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "ModifyLoadBalancerAttributes", value(in.LoadBalancerArn), v.Tags, nil); e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	for _, a := range in.Attributes {
		k := value(a.Key)
		if seen[k] {
			return nil, invalid("Duplicate attribute")
		}
		seen[k] = true
		switch k {
		case "deletion_protection.enabled":
			if value(a.Value) != "true" && value(a.Value) != "false" {
				return nil, invalid("Deletion protection must be true or false")
			}
			v.DeletionProtection = value(a.Value) == "true"
		case "idle_timeout.timeout_seconds":
			n, e := strconv.Atoi(value(a.Value))
			if e != nil || n < 1 || n > 4000 {
				return nil, invalid("Idle timeout must be between 1 and 4000 seconds")
			}
			v.IdleTimeout = time.Duration(n) * time.Second
		default:
			return nil, unsupported("Unsupported load balancer attribute: " + k)
		}
	}
	v.Version++
	v.NextReconcile = s.clock.Now()
	if e = tx.PutLoadBalancer(v); e != nil {
		return nil, e
	}
	return &api.ModifyLoadBalancerAttributesOutput{Attributes: loadBalancerAttributes(v)}, nil
}
func (s *Service) touchLoadBalancer(tx Transaction, sc Scope, a string) error {
	v, e := loadBalancer(tx, sc, a)
	if e != nil {
		return e
	}
	v.Version++
	v.NextReconcile = s.clock.Now()
	return tx.PutLoadBalancer(v)
}
func assignAttachmentGenerations(tx Transaction, v *LoadBalancerRecord, zones api.AvailabilityZones) error {
	if v.AttachmentGenerations == nil {
		v.AttachmentGenerations = map[string]uint64{}
	}
	for _, zone := range zones {
		subnet := value(zone.SubnetId)
		if v.AttachmentGenerations[subnet] != 0 {
			continue
		}
		id, e := tx.NextID()
		if e != nil {
			return e
		}
		v.AttachmentGenerations[subnet] = id
	}
	return nil
}
