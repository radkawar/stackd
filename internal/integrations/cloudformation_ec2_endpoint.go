package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"time"
)

type cfnEC2VPCEndpoint struct{ commands StepFunctionsCommands }

func cfnEndpointDNS(p cloudformation.Properties) (map[string]any, error) {
	value, ok := p["DnsOptions"]
	if !ok {
		return nil, nil
	}
	options, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("DnsOptions must be an object")
	}
	if err := cfnComputeProperties(options, "DnsRecordIpType", "PrivateDnsOnlyForInboundResolverEndpoint"); err != nil {
		return nil, err
	}
	if err := cfnComputeStrings(options, "DnsRecordIpType", "PrivateDnsOnlyForInboundResolverEndpoint"); err != nil {
		return nil, err
	}
	out := map[string]any{}
	if kind := cfnComputeString(options, "DnsRecordIpType"); kind != "" && kind != "not-specified" {
		if kind != "ipv4" && kind != "service-defined" {
			return nil, fmt.Errorf("only IPv4 endpoint DNS controls are supported")
		}
		out["DnsRecordIpType"] = kind
	}
	switch cfnComputeString(options, "PrivateDnsOnlyForInboundResolverEndpoint") {
	case "", "NotSpecified":
	case "OnlyInboundResolver":
		out["PrivateDnsOnlyForInboundResolverEndpoint"] = true
	case "AllResolvers":
		out["PrivateDnsOnlyForInboundResolverEndpoint"] = false
	default:
		return nil, fmt.Errorf("invalid PrivateDnsOnlyForInboundResolverEndpoint")
	}
	return out, nil
}
func cfnEndpointPolicy(p cloudformation.Properties) (string, error) {
	value, exists := p["PolicyDocument"]
	if !exists {
		return "", nil
	}
	if text, ok := value.(string); ok {
		var policy map[string]any
		if json.Unmarshal([]byte(text), &policy) != nil || policy["Statement"] == nil {
			return "", fmt.Errorf("PolicyDocument must be a JSON policy")
		}
		return text, nil
	}
	policy, ok := value.(map[string]any)
	if !ok || policy["Statement"] == nil {
		return "", fmt.Errorf("PolicyDocument must be a policy object or JSON string")
	}
	data, err := json.Marshal(policy)
	return string(data), err
}
func (h cfnEC2VPCEndpoint) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "VpcId", "VpcEndpointType", "ServiceName", "ServiceRegion", "SubnetIds", "SecurityGroupIds", "RouteTableIds", "PolicyDocument", "PrivateDnsEnabled", "DnsOptions", "IpAddressType", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "VpcId", "ServiceName"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "VpcId", "ServiceName", "ServiceRegion", "VpcEndpointType", "IpAddressType"); err != nil {
		return err
	}
	if err := cfnEC2Booleans(p, "PrivateDnsEnabled"); err != nil {
		return err
	}
	if err := cfnNetworkLists(p, "SubnetIds", "SecurityGroupIds", "RouteTableIds"); err != nil {
		return err
	}
	kind := cfnComputeString(p, "VpcEndpointType")
	if kind == "" {
		kind = "Gateway"
	}
	if kind != "Gateway" && kind != "Interface" {
		return fmt.Errorf("only Gateway and Interface endpoint controls are supported")
	}
	subnets, _ := cfnComputeStringList(p, "SubnetIds")
	groups, _ := cfnComputeStringList(p, "SecurityGroupIds")
	routes, _ := cfnComputeStringList(p, "RouteTableIds")
	if kind == "Gateway" && (len(subnets) > 0 || len(groups) > 0 || p["DnsOptions"] != nil || p["PrivateDnsEnabled"] == true) {
		return fmt.Errorf("gateway endpoints do not support interface or private DNS configuration")
	}
	if kind == "Interface" && (len(subnets) == 0 || len(routes) > 0) {
		return fmt.Errorf("interface endpoints require subnets and cannot use route tables")
	}
	if ip := cfnComputeString(p, "IpAddressType"); ip != "" && ip != "ipv4" && ip != "not-specified" {
		return fmt.Errorf("only IPv4 endpoint controls are supported")
	}
	if _, err := cfnEndpointDNS(p); err != nil {
		return err
	}
	if _, err := cfnEndpointPolicy(p); err != nil {
		return err
	}
	_, err := cfnEC2NetworkTags(p)
	return err
}
func (h cfnEC2VPCEndpoint) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "VpcId", "VpcEndpointType", "ServiceName", "ServiceRegion"), h.Validate(b)
}
func (h cfnEC2VPCEndpoint) describe(ctx context.Context, id string) (api.VpcEndpoint, error) {
	out, err := cfnComputeCall[api.DescribeVpcEndpointsResult](ctx, h.commands, "ec2", "DescribeVpcEndpoints", map[string]any{"VpcEndpointIds": []string{id}})
	if err != nil {
		return api.VpcEndpoint{}, err
	}
	if len(out.VpcEndpoints) != 1 {
		return api.VpcEndpoint{}, cfnEC2NotFound("VPC endpoint")
	}
	return out.VpcEndpoints[0], nil
}
func (h cfnEC2VPCEndpoint) result(v api.VpcEndpoint) cloudformation.ResourceResult {
	id := cfnComputeValue(v.VpcEndpointId)
	created := ""
	if v.CreationTimestamp != nil {
		created = v.CreationTimestamp.UTC().Format(time.RFC3339Nano)
	}
	dns := []string{}
	for _, entry := range v.DnsEntries {
		dns = append(dns, cfnComputeValue(entry.HostedZoneId)+":"+cfnComputeValue(entry.DnsName))
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "CreationTimestamp": created, "NetworkInterfaceIds": cfnNetworkStrings(v.NetworkInterfaceIds), "DnsEntries": dns}}
}
func (h cfnEC2VPCEndpoint) input(p cloudformation.Properties) (map[string]any, error) {
	input := cfnComputeCopy(p, "VpcId", "VpcEndpointType", "ServiceName", "ServiceRegion", "SubnetIds", "SecurityGroupIds", "RouteTableIds", "PrivateDnsEnabled")
	if ip := cfnComputeString(p, "IpAddressType"); ip != "" && ip != "not-specified" {
		input["IpAddressType"] = ip
	}
	if p["DnsOptions"] != nil {
		dns, err := cfnEndpointDNS(p)
		if err != nil {
			return nil, err
		}
		input["DnsOptions"] = dns
	}
	if p["PolicyDocument"] != nil {
		policy, err := cfnEndpointPolicy(p)
		if err != nil {
			return nil, err
		}
		input["PolicyDocument"] = policy
	}
	return input, nil
}
func (h cfnEC2VPCEndpoint) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if id == "" {
		input, err := h.input(r.Properties)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		input["ClientToken"] = cfnNetworkToken(r)
		input["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "vpc-endpoint")
		out, err := cfnComputeCall[api.CreateVpcEndpointResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateVpcEndpoint", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		id = cfnComputeValue(out.VpcEndpoint.VpcEndpointId)
	}
	v, err := h.describe(ctx, id)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcEndpointId)); err != nil {
		return h.result(v), err
	}
	if cfnComputeValue(v.State) == "deleted" {
		return h.result(v), fmt.Errorf("VPC endpoint incarnation was deleted")
	}
	return h.result(v), nil
}
func (h cfnEC2VPCEndpoint) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if replacement {
		return cloudformation.ResourceResult{}, fmt.Errorf("endpoint update requires replacement")
	}
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	result := h.result(v)
	tags := cfnEC2Tags(v.Tags)
	if err = cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	input := map[string]any{"VpcEndpointId": r.PhysicalID, "PrivateDnsEnabled": cfnComputeDefault(r.Properties, "PrivateDnsEnabled", false), "IpAddressType": "ipv4"}
	if r.Properties["PolicyDocument"] == nil {
		input["ResetPolicy"] = true
	} else {
		policy, err := cfnEndpointPolicy(r.Properties)
		if err != nil {
			return result, err
		}
		input["PolicyDocument"] = policy
	}
	if r.Properties["DnsOptions"] != nil {
		dns, err := cfnEndpointDNS(r.Properties)
		if err != nil {
			return result, err
		}
		input["DnsOptions"] = dns
	} else if v.DnsOptions != nil {
		input["DnsOptions"] = map[string]any{}
	}
	for _, set := range []struct {
		property, add, remove string
		current               []string
	}{{"RouteTableIds", "AddRouteTableIds", "RemoveRouteTableIds", cfnNetworkStrings(v.RouteTableIds)}, {"SubnetIds", "AddSubnetIds", "RemoveSubnetIds", cfnNetworkStrings(v.SubnetIds)}} {
		desired, _ := cfnComputeStringList(r.Properties, set.property)
		if add := cfnNetworkDifference(desired, set.current); len(add) > 0 {
			input[set.add] = add
		}
		if remove := cfnNetworkDifference(set.current, desired); len(remove) > 0 {
			input[set.remove] = remove
		}
	}
	if cfnComputeValue(v.VpcEndpointType) == "Interface" {
		current := []string{}
		for _, group := range v.Groups {
			current = append(current, cfnComputeValue(group.GroupId))
		}
		desired, _ := cfnComputeStringList(r.Properties, "SecurityGroupIds")
		if len(desired) == 0 {
			out, err := cfnComputeCall[api.DescribeSecurityGroupsResult](ctx, h.commands, "ec2", "DescribeSecurityGroups", map[string]any{"Filters": []map[string]any{{"Name": "vpc-id", "Values": []string{cfnComputeValue(v.VpcId)}}, {"Name": "group-name", "Values": []string{"default"}}}})
			if err != nil {
				return result, err
			}
			for _, group := range out.SecurityGroups {
				desired = append(desired, cfnComputeValue(group.GroupId))
			}
		}
		if add := cfnNetworkDifference(desired, current); len(add) > 0 {
			input["AddSecurityGroupIds"] = add
		}
		if remove := cfnNetworkDifference(current, desired); len(remove) > 0 {
			input["RemoveSecurityGroupIds"] = remove
		}
	}
	if err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "ModifyVpcEndpoint", input); err != nil {
		return result, err
	}
	if err = cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, tags); err != nil {
		return result, err
	}
	v, err = h.describe(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	return h.result(v), nil
}
func (h cfnEC2VPCEndpoint) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2Absent(err)
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcEndpointId)); err != nil {
		return err
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteVpcEndpoints", map[string]any{"VpcEndpointIds": []string{r.PhysicalID}}))
}
func (h cfnEC2VPCEndpoint) projection(v api.VpcEndpoint) cloudformation.Properties {
	result := h.result(v)
	p := cloudformation.Properties{"Id": result.Ref, "VpcId": cfnComputeValue(v.VpcId), "VpcEndpointType": cfnComputeValue(v.VpcEndpointType), "ServiceName": cfnComputeValue(v.ServiceName), "ServiceRegion": cfnComputeValue(v.ServiceRegion), "IpAddressType": cfnComputeValue(v.IpAddressType), "Tags": cfnEC2NetworkUserTags(v.Tags), "RouteTableIds": cfnNetworkStrings(v.RouteTableIds), "SubnetIds": cfnNetworkStrings(v.SubnetIds), "PolicyDocument": cfnComputeValue(v.PolicyDocument)}
	for key, value := range result.Attributes {
		p[key] = value
	}
	if v.PrivateDnsEnabled != nil {
		p["PrivateDnsEnabled"] = bool(*v.PrivateDnsEnabled)
	}
	groups := []string{}
	for _, group := range v.Groups {
		groups = append(groups, cfnComputeValue(group.GroupId))
	}
	p["SecurityGroupIds"] = groups
	if v.DnsOptions != nil {
		options := map[string]any{}
		if v.DnsOptions.DnsRecordIpType != nil {
			options["DnsRecordIpType"] = cfnComputeValue(v.DnsOptions.DnsRecordIpType)
		}
		if v.DnsOptions.PrivateDnsOnlyForInboundResolverEndpoint != nil {
			mode := "AllResolvers"
			if bool(*v.DnsOptions.PrivateDnsOnlyForInboundResolverEndpoint) {
				mode = "OnlyInboundResolver"
			}
			options["PrivateDnsOnlyForInboundResolverEndpoint"] = mode
		}
		p["DnsOptions"] = options
	}
	return p
}
func (h cfnEC2VPCEndpoint) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcEndpointId)); err != nil {
		return nil, err
	}
	if cfnComputeValue(v.State) == "deleted" {
		return nil, cfnEC2NotFound("VPC endpoint")
	}
	return h.projection(v), nil
}
func (h cfnEC2VPCEndpoint) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	for input := map[string]any{}; ; {
		out, err := cfnComputeCall[api.DescribeVpcEndpointsResult](ctx, h.commands, "ec2", "DescribeVpcEndpoints", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.VpcEndpoints {
			if cfnComputeValue(v.State) == "deleted" || cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcEndpointId)) != nil {
				continue
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.VpcEndpointId), Properties: h.projection(v)})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEC2VPCEndpoint) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcEndpointId)); err != nil {
		return false, err
	}
	return cfnComputeValue(v.State) == "available", nil
}
func (h cfnEC2VPCEndpoint) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcEndpointId)); err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	return h.result(v), nil
}
func (h cfnEC2VPCEndpoint) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	result := cfnEC2IDResult(id)
	if err != nil || id == "" {
		if err == nil {
			err = cfnEC2NotFound(r.Type)
		}
		return result, err
	}
	r.PhysicalID = id
	return h.Result(ctx, r)
}
