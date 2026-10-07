package integrations

import (
	"context"
	"fmt"
	"slices"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

func (h cfnEC2Instance) ReplacementPlan(before, after cloudformation.Properties) (string, error) {
	replace, err := h.Replacement(before, after)
	if err != nil {
		return "", err
	}
	if replace {
		return "True", nil
	}
	if cfnComputeChanged(before, after, "InstanceType", "UserData", "SecurityGroupIds", "Tenancy", "AdditionalInfo", "Affinity", "EbsOptimized", "HostId", "KernelId", "PrivateDnsNameOptions", "RamdiskId") {
		return "Conditional", nil
	}
	return "False", nil
}

// ReplacementForResource needs the current caller context and previous physical
// incarnation: conditional AWS updates cannot be decided from instance-type
// spelling or a cached deployment model. The controller's contextual optional
// replacement boundary invokes this before effects.
func (h cfnEC2Instance) ReplacementForResource(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil || replace {
		return replace, err
	}
	if !cfnComputeChanged(r.Previous, r.Properties, "InstanceType", "UserData", "SecurityGroupIds", "Tenancy") {
		return false, nil
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.InstanceId)); err != nil {
		return false, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Tenancy") {
		wanted := cfnComputeString(r.Properties, "Tenancy")
		if wanted == "" {
			wanted = "default"
		}
		current := "default"
		if v.Placement != nil && cfnComputeValue(v.Placement.Tenancy) != "" {
			current = cfnComputeValue(v.Placement.Tenancy)
		}
		if wanted != current {
			return true, nil
		}
	}
	if cfnComputeChanged(r.Previous, r.Properties, "InstanceType", "UserData") && cfnComputeValue(v.RootDeviceType) != "ebs" {
		return true, nil
	}
	if cfnComputeChanged(r.Previous, r.Properties, "SecurityGroupIds") && len(v.NetworkInterfaces) != 1 {
		return true, nil
	}
	if cfnComputeChanged(r.Previous, r.Properties, "InstanceType") {
		wanted := cfnComputeString(r.Properties, "InstanceType")
		if wanted == "" {
			wanted = "m1.small"
		}
		if wanted == cfnComputeValue(v.InstanceType) {
			return false, nil
		}
		out, err := cfnComputeCall[api.DescribeInstanceTypesResult](ctx, h.commands, "ec2", "DescribeInstanceTypes", map[string]any{"InstanceTypes": []string{wanted}})
		if err != nil {
			return false, err
		}
		if len(out.InstanceTypes) != 1 || out.InstanceTypes[0].ProcessorInfo == nil {
			return false, fmt.Errorf("EC2 did not describe the target instance type architecture")
		}
		if !slices.Contains(out.InstanceTypes[0].ProcessorInfo.SupportedArchitectures, api.ArchitectureType(cfnComputeValue(v.Architecture))) {
			return true, nil
		}
	}
	return false, nil
}
