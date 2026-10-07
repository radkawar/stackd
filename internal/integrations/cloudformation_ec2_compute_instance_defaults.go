package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

func cfnEC2InstanceDesiredType(r cloudformation.ResourceRequest) string {
	if value, found := r.Properties["InstanceType"]; found {
		return value.(string)
	}
	if r.Previous["InstanceType"] != nil {
		return "m1.small"
	}
	return ""
}

func (h cfnEC2Instance) groups(ctx context.Context, r cloudformation.ResourceRequest, v api.Instance) error {
	raw, found := r.Properties["SecurityGroupIds"]
	if !found && r.Previous["SecurityGroupIds"] == nil {
		return nil
	}
	if !found {
		out, err := cfnComputeCall[api.DescribeSecurityGroupsResult](ctx, h.commands, "ec2", "DescribeSecurityGroups", map[string]any{"Filters": []any{map[string]any{"Name": "vpc-id", "Values": []string{cfnComputeValue(v.VpcId)}}, map[string]any{"Name": "group-name", "Values": []string{"default"}}}})
		if err != nil {
			return err
		}
		if len(out.SecurityGroups) != 1 {
			return fmt.Errorf("EC2 did not describe exactly one VPC default security group")
		}
		raw = []any{cfnComputeValue(out.SecurityGroups[0].GroupId)}
	}
	groups, err := cfnComputeStringList(map[string]any{"SecurityGroupIds": raw}, "SecurityGroupIds")
	if err != nil {
		return err
	}
	match := len(groups) == len(v.SecurityGroups)
	for _, desired := range groups {
		found := false
		for _, actual := range v.SecurityGroups {
			if desired == cfnComputeValue(actual.GroupId) {
				found = true
				break
			}
		}
		if !found {
			match = false
			break
		}
	}
	if match {
		return nil
	}
	return cfnComputeRun(ctx, h.commands, "ec2", "ModifyInstanceAttribute", map[string]any{"InstanceId": r.PhysicalID, "Groups": groups})
}

func (h cfnEC2Instance) metadata(ctx context.Context, r cloudformation.ResourceRequest, v api.Instance) error {
	raw, found := r.Properties["MetadataOptions"]
	if !found && r.Previous["MetadataOptions"] == nil {
		return nil
	}
	options := map[string]any{}
	if found {
		value, ok := cfnComputeObject(raw)
		if !ok {
			return fmt.Errorf("MetadataOptions must be an object")
		}
		if err := cfnComputeProperties(value, "HttpEndpoint", "HttpTokens", "HttpPutResponseHopLimit", "HttpProtocolIpv6", "InstanceMetadataTags"); err != nil {
			return err
		}
		options = cfnComputeCopy(value, "HttpEndpoint", "HttpTokens", "HttpPutResponseHopLimit", "HttpProtocolIpv6", "InstanceMetadataTags")
	}
	previous, _ := cfnComputeObject(r.Previous["MetadataOptions"])
	removed := false
	for key := range previous {
		if _, found := options[key]; !found {
			removed = true
			break
		}
	}
	if removed {
		// These are the configured EC2 owner's ordinary launch defaults; IMDSv2
		// AMI defaults are read from the real image owner under current IAM.
		defaults := map[string]any{"HttpEndpoint": "enabled", "HttpProtocolIpv6": "disabled", "HttpPutResponseHopLimit": 1, "HttpTokens": "optional", "InstanceMetadataTags": "disabled"}
		image, err := cfnComputeCall[api.ImageAttribute](ctx, h.commands, "ec2", "DescribeImageAttribute", map[string]any{"ImageId": cfnComputeValue(v.ImageId), "Attribute": "imdsSupport"})
		if err != nil {
			return err
		}
		if image.ImdsSupport != nil && cfnComputeValue(image.ImdsSupport.Value) == "v2.0" {
			defaults["HttpTokens"] = "required"
			defaults["HttpPutResponseHopLimit"] = 2
		}
		for key := range previous {
			if _, found := options[key]; !found {
				options[key] = defaults[key]
			}
		}
	}
	actual, err := cfnEC2ComputeProjection(v.MetadataOptions)
	if err != nil {
		return err
	}
	changed := false
	for key, value := range options {
		if !cfnEC2ComputeEqual(value, actual[key]) {
			changed = true
			break
		}
	}
	if !changed {
		return nil
	}
	options["InstanceId"] = r.PhysicalID
	return cfnComputeRun(ctx, h.commands, "ec2", "ModifyInstanceMetadataOptions", options)
}
