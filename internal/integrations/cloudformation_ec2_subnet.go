package integrations

import (
	"context"
	"fmt"
	"net/netip"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

type cfnEC2Subnet struct{ commands StepFunctionsCommands }

func (h cfnEC2Subnet) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "VpcId", "CidrBlock", "AvailabilityZone", "AvailabilityZoneId", "MapPublicIpOnLaunch", "EnableDns64", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "VpcId", "CidrBlock"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "VpcId", "CidrBlock", "AvailabilityZone", "AvailabilityZoneId"); err != nil {
		return err
	}
	if p["AvailabilityZone"] != nil && p["AvailabilityZoneId"] != nil {
		return fmt.Errorf("AvailabilityZone and AvailabilityZoneId are mutually exclusive")
	}
	if err := cfnEC2Booleans(p, "MapPublicIpOnLaunch", "EnableDns64"); err != nil {
		return err
	}
	_, err := cfnEC2NetworkTags(p)
	return err
}
func (h cfnEC2Subnet) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	before, oldErr := netip.ParsePrefix(cfnComputeString(a, "CidrBlock"))
	after, newErr := netip.ParsePrefix(cfnComputeString(b, "CidrBlock"))
	return cfnComputeChanged(a, b, "VpcId", "AvailabilityZone", "AvailabilityZoneId") || oldErr != nil || newErr != nil || before.Masked() != after.Masked(), nil
}
func (h cfnEC2Subnet) describe(ctx context.Context, id string) (api.Subnet, error) {
	out, err := cfnComputeCall[api.DescribeSubnetsResult](ctx, h.commands, "ec2", "DescribeSubnets", map[string]any{"SubnetIds": []string{id}})
	if err != nil {
		return api.Subnet{}, err
	}
	if len(out.Subnets) != 1 {
		return api.Subnet{}, fmt.Errorf("subnet %s not found", id)
	}
	return out.Subnets[0], nil
}
func (h cfnEC2Subnet) result(v api.Subnet) cloudformation.ResourceResult {
	id := cfnComputeValue(v.SubnetId)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"SubnetId": id, "VpcId": cfnComputeValue(v.VpcId), "AvailabilityZone": cfnComputeValue(v.AvailabilityZone), "AvailabilityZoneId": cfnComputeValue(v.AvailabilityZoneId), "Ipv6CidrBlocks": []string{}}}
}
func (h cfnEC2Subnet) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if id == "" {
		input := cfnComputeCopy(r.Properties, "VpcId", "CidrBlock", "AvailabilityZone", "AvailabilityZoneId")
		input["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "subnet")
		out, err := cfnComputeCall[api.CreateSubnetResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateSubnet", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		id = cfnComputeValue(out.Subnet.SubnetId)
	}
	r.PhysicalID = id
	v, err := h.describe(ctx, id)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	result := h.result(v)
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.SubnetId)); err != nil {
		return result, err
	}
	return result, h.configure(ctx, r)
}
func (h cfnEC2Subnet) configure(ctx context.Context, r cloudformation.ResourceRequest) error {
	for _, key := range []string{"MapPublicIpOnLaunch", "EnableDns64"} {
		if err := cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "ModifySubnetAttribute", map[string]any{"SubnetId": r.PhysicalID, key: map[string]any{"Value": cfnComputeDefault(r.Properties, key, false)}}); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnEC2Subnet) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if replacement {
		return cloudformation.ResourceResult{}, fmt.Errorf("subnet update requires replacement")
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
	if err = h.configure(ctx, r); err != nil {
		return result, err
	}
	return result, cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, tags)
}
func (h cfnEC2Subnet) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2Absent(err)
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.SubnetId)); err != nil {
		return err
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteSubnet", map[string]any{"SubnetId": r.PhysicalID}))
}
func (h cfnEC2Subnet) projection(ctx context.Context, v api.Subnet) (cloudformation.Properties, error) {
	p := cloudformation.Properties{"SubnetId": cfnComputeValue(v.SubnetId), "VpcId": cfnComputeValue(v.VpcId), "CidrBlock": cfnComputeValue(v.CidrBlock), "AvailabilityZone": cfnComputeValue(v.AvailabilityZone), "AvailabilityZoneId": cfnComputeValue(v.AvailabilityZoneId), "Tags": cfnEC2NetworkUserTags(v.Tags), "Ipv6CidrBlocks": []string{}}
	if v.MapPublicIpOnLaunch != nil {
		p["MapPublicIpOnLaunch"] = bool(*v.MapPublicIpOnLaunch)
	}
	if v.EnableDns64 != nil {
		p["EnableDns64"] = bool(*v.EnableDns64)
	}
	if v.BlockPublicAccessStates != nil {
		p["BlockPublicAccessStates"] = map[string]any{"InternetGatewayBlockMode": cfnComputeValue(v.BlockPublicAccessStates.InternetGatewayBlockMode)}
	}
	out, err := cfnComputeCall[api.DescribeNetworkAclsResult](ctx, h.commands, "ec2", "DescribeNetworkAcls", map[string]any{"Filters": []map[string]any{{"Name": "association.subnet-id", "Values": []string{cfnComputeValue(v.SubnetId)}}}})
	if err != nil {
		return nil, err
	}
	for _, acl := range out.NetworkAcls {
		for _, association := range acl.Associations {
			if cfnComputeValue(association.SubnetId) == cfnComputeValue(v.SubnetId) {
				p["NetworkAclAssociationId"] = cfnComputeValue(association.NetworkAclAssociationId)
			}
		}
	}
	return p, nil
}
func (h cfnEC2Subnet) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.SubnetId)); err != nil {
		return nil, err
	}
	return h.projection(ctx, v)
}
func (h cfnEC2Subnet) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	for input := map[string]any{}; ; {
		out, err := cfnComputeCall[api.DescribeSubnetsResult](ctx, h.commands, "ec2", "DescribeSubnets", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Subnets {
			if !r.CloudControl && cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.SubnetId)) != nil {
				continue
			}
			p, err := h.projection(ctx, v)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.SubnetId), Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEC2Subnet) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.SubnetId)); err != nil {
		return false, err
	}
	return cfnComputeValue(v.State) == "available", nil
}

func (h cfnEC2Subnet) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.Read(ctx, r)
	result := cfnEC2IDResult(r.PhysicalID)
	if err != nil {
		return result, err
	}
	result.Attributes = cfnComputeCopy(p, "SubnetId", "VpcId", "AvailabilityZone", "AvailabilityZoneId", "Ipv6CidrBlocks", "NetworkAclAssociationId", "BlockPublicAccessStates")
	return result, nil
}
func (h cfnEC2Subnet) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	result := cfnEC2IDResult(id)
	if err != nil || id == "" {
		if err == nil {
			err = cfnEC2NotFound(r.Type)
		}
		return result, err
	}
	r.PhysicalID = id
	v, err := h.describe(ctx, id)
	if err != nil {
		return result, err
	}
	result = h.result(v)
	if err = cfnEC2NativeOwned(ctx, h.commands, r, id); err != nil {
		return result, err
	}
	return result, h.configure(ctx, r)
}
