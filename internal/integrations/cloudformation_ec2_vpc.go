package integrations

import (
	"context"
	"fmt"
	"net/netip"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

type cfnEC2VPC struct{ commands StepFunctionsCommands }

func (h cfnEC2VPC) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "CidrBlock", "EnableDnsHostnames", "EnableDnsSupport", "InstanceTenancy", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "CidrBlock"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "CidrBlock", "InstanceTenancy"); err != nil {
		return err
	}
	if value := cfnComputeString(p, "InstanceTenancy"); value != "" && value != "default" {
		return fmt.Errorf("only default VPC tenancy is implemented")
	}
	if err := cfnEC2Booleans(p, "EnableDnsHostnames", "EnableDnsSupport"); err != nil {
		return err
	}
	_, err := cfnEC2NetworkTags(p)
	return err
}
func (h cfnEC2VPC) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	before, oldErr := netip.ParsePrefix(cfnComputeString(a, "CidrBlock"))
	after, newErr := netip.ParsePrefix(cfnComputeString(b, "CidrBlock"))
	return oldErr != nil || newErr != nil || before.Masked() != after.Masked(), nil
}
func (h cfnEC2VPC) describe(ctx context.Context, id string) (api.Vpc, error) {
	out, err := cfnComputeCall[api.DescribeVpcsResult](ctx, h.commands, "ec2", "DescribeVpcs", map[string]any{"VpcIds": []string{id}})
	if err != nil {
		return api.Vpc{}, err
	}
	if len(out.Vpcs) != 1 {
		return api.Vpc{}, fmt.Errorf("VPC %s not found", id)
	}
	return out.Vpcs[0], nil
}
func (h cfnEC2VPC) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if id == "" {
		input := cfnComputeCopy(r.Properties, "CidrBlock", "InstanceTenancy")
		input["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "vpc")
		out, err := cfnComputeCall[api.CreateVpcResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateVpc", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		id = cfnComputeValue(out.Vpc.VpcId)
	}
	r.PhysicalID = id
	result := cfnEC2IDResult(id)
	current, err := h.describe(ctx, id)
	if err != nil {
		return result, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, id); err != nil {
		return result, err
	}
	if err = h.configure(ctx, r); err != nil {
		return result, err
	}
	result.Attributes, err = h.attributes(ctx, current)
	return result, err
}
func (h cfnEC2VPC) configure(ctx context.Context, r cloudformation.ResourceRequest) error {
	for _, key := range []string{"EnableDnsSupport", "EnableDnsHostnames"} {
		fallback := key == "EnableDnsSupport"
		if err := cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "ModifyVpcAttribute", map[string]any{"VpcId": r.PhysicalID, key: map[string]any{"Value": cfnComputeDefault(r.Properties, key, fallback)}}); err != nil {
			return err
		}
	}
	return nil
}
func (h cfnEC2VPC) attributes(ctx context.Context, v api.Vpc) (map[string]any, error) {
	id := cfnComputeValue(v.VpcId)
	attrs := map[string]any{"VpcId": id, "CidrBlock": cfnComputeValue(v.CidrBlock), "Ipv6CidrBlocks": []string{}}
	associations := []string{}
	for _, a := range v.CidrBlockAssociationSet {
		associations = append(associations, cfnComputeValue(a.AssociationId))
	}
	attrs["CidrBlockAssociations"] = associations
	groups, err := cfnComputeCall[api.DescribeSecurityGroupsResult](ctx, h.commands, "ec2", "DescribeSecurityGroups", map[string]any{"Filters": []map[string]any{{"Name": "vpc-id", "Values": []string{id}}, {"Name": "group-name", "Values": []string{"default"}}}})
	if err != nil {
		return nil, err
	}
	if len(groups.SecurityGroups) == 1 {
		attrs["DefaultSecurityGroup"] = cfnComputeValue(groups.SecurityGroups[0].GroupId)
	}
	acls, err := cfnComputeCall[api.DescribeNetworkAclsResult](ctx, h.commands, "ec2", "DescribeNetworkAcls", map[string]any{"Filters": []map[string]any{{"Name": "vpc-id", "Values": []string{id}}, {"Name": "default", "Values": []string{"true"}}}})
	if err != nil {
		return nil, err
	}
	if len(acls.NetworkAcls) == 1 {
		attrs["DefaultNetworkAcl"] = cfnComputeValue(acls.NetworkAcls[0].NetworkAclId)
	}
	return attrs, nil
}
func (h cfnEC2VPC) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if replacement {
		return cloudformation.ResourceResult{}, fmt.Errorf("VPC update requires replacement")
	}
	v, err := h.describe(ctx, r.PhysicalID)
	result := cfnEC2IDResult(r.PhysicalID)
	if err != nil {
		return result, err
	}
	tags := cfnEC2Tags(v.Tags)
	if err = cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	if err = h.configure(ctx, r); err != nil {
		return result, err
	}
	if err = cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, tags); err != nil {
		return result, err
	}
	result.Attributes, err = h.attributes(ctx, v)
	return result, err
}
func (h cfnEC2VPC) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2Absent(err)
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcId)); err != nil {
		return err
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteVpc", map[string]any{"VpcId": r.PhysicalID}))
}
func (h cfnEC2VPC) projection(ctx context.Context, v api.Vpc) (cloudformation.Properties, error) {
	p := cloudformation.Properties{"VpcId": cfnComputeValue(v.VpcId), "CidrBlock": cfnComputeValue(v.CidrBlock), "InstanceTenancy": cfnComputeValue(v.InstanceTenancy), "Tags": cfnEC2NetworkUserTags(v.Tags)}
	for _, attribute := range []struct{ request, property string }{{"enableDnsSupport", "EnableDnsSupport"}, {"enableDnsHostnames", "EnableDnsHostnames"}} {
		out, err := cfnComputeCall[api.DescribeVpcAttributeResult](ctx, h.commands, "ec2", "DescribeVpcAttribute", map[string]any{"VpcId": cfnComputeValue(v.VpcId), "Attribute": attribute.request})
		if err != nil {
			return nil, err
		}
		value := out.EnableDnsSupport
		if attribute.request == "enableDnsHostnames" {
			value = out.EnableDnsHostnames
		}
		if value != nil && value.Value != nil {
			p[attribute.property] = bool(*value.Value)
		}
	}
	attrs, err := h.attributes(ctx, v)
	if err != nil {
		return nil, err
	}
	for key, value := range attrs {
		p[key] = value
	}
	return p, nil
}
func (h cfnEC2VPC) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcId)); err != nil {
		return nil, err
	}
	return h.projection(ctx, v)
}
func (h cfnEC2VPC) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	for input := map[string]any{}; ; {
		out, err := cfnComputeCall[api.DescribeVpcsResult](ctx, h.commands, "ec2", "DescribeVpcs", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Vpcs {
			if !r.CloudControl && cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcId)) != nil {
				continue
			}
			p, err := h.projection(ctx, v)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.VpcId), Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEC2VPC) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VpcId)); err != nil {
		return false, err
	}
	return cfnComputeValue(v.State) == "available", nil
}
func (h cfnEC2VPC) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
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
	if err = cfnEC2NativeOwned(ctx, h.commands, r, id); err != nil {
		return result, err
	}
	if err = h.configure(ctx, r); err != nil {
		return result, err
	}
	result.Attributes, err = h.attributes(ctx, v)
	return result, err
}
