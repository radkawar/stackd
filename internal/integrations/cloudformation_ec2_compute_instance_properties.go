package integrations

import (
	"context"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

// CFN uses a few spellings and value shapes different from the EC2 SDK. Copy
// only the changed objects so resolving a launch never mutates the template.
func cfnEC2InstanceLaunchProperties(p cloudformation.Properties, in map[string]any) error {
	if raw, found := p["CreditSpecification"]; found {
		credits, ok := cfnComputeObject(raw)
		if !ok {
			return fmt.Errorf("CreditSpecification must be an object")
		}
		if err := cfnComputeProperties(credits, "CPUCredits"); err != nil {
			return err
		}
		if err := cfnComputeRequired(credits, "CPUCredits"); err != nil {
			return err
		}
		if err := cfnComputeStrings(credits, "CPUCredits"); err != nil {
			return err
		}
		in["CreditSpecification"] = map[string]any{"CpuCredits": credits["CPUCredits"]}
	}
	if raw, found := p["BlockDeviceMappings"]; found {
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("BlockDeviceMappings must be a list")
		}
		mappings := make([]any, 0, len(list))
		for _, raw := range list {
			mapping, ok := cfnComputeObject(raw)
			if !ok {
				return fmt.Errorf("BlockDeviceMappings entries must be objects")
			}
			if err := cfnComputeProperties(mapping, "DeviceName", "Ebs", "VirtualName", "NoDevice"); err != nil {
				return err
			}
			if err := cfnComputeRequired(mapping, "DeviceName"); err != nil {
				return err
			}
			if err := cfnComputeStrings(mapping, "DeviceName", "VirtualName"); err != nil {
				return err
			}
			if raw, found := mapping["Ebs"]; found {
				ebs, ok := cfnComputeObject(raw)
				if !ok {
					return fmt.Errorf("BlockDeviceMappings Ebs must be an object")
				}
				if err := cfnComputeProperties(ebs, "SnapshotId", "VolumeType", "KmsKeyId", "Encrypted", "Iops", "VolumeSize", "DeleteOnTermination"); err != nil {
					return err
				}
			}
			copy := cfnComputeCopy(mapping, "DeviceName", "Ebs", "VirtualName", "NoDevice")
			if _, found := mapping["NoDevice"]; found {
				if noDevice, ok := cfnComputeObject(mapping["NoDevice"]); !ok || len(noDevice) != 0 {
					return fmt.Errorf("NoDevice must be an empty object")
				}
				copy["NoDevice"] = ""
			}
			mappings = append(mappings, copy)
		}
		in["BlockDeviceMappings"] = mappings
	}
	if raw, found := p["NetworkInterfaces"]; found {
		list, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("NetworkInterfaces must be a list")
		}
		interfaces := make([]any, 0, len(list))
		for _, raw := range list {
			iface, ok := cfnComputeObject(raw)
			if !ok {
				return fmt.Errorf("NetworkInterfaces entries must be objects")
			}
			if err := cfnComputeProperties(iface, "Description", "PrivateIpAddress", "PrivateIpAddresses", "SecondaryPrivateIpAddressCount", "DeviceIndex", "GroupSet", "Ipv6Addresses", "SubnetId", "AssociatePublicIpAddress", "NetworkInterfaceId", "AssociateCarrierIpAddress", "EnaSrdSpecification", "Ipv6AddressCount", "DeleteOnTermination"); err != nil {
				return err
			}
			copy := cfnComputeCopy(iface, "Description", "PrivateIpAddress", "PrivateIpAddresses", "SecondaryPrivateIpAddressCount", "DeviceIndex", "Ipv6Addresses", "SubnetId", "AssociatePublicIpAddress", "NetworkInterfaceId", "AssociateCarrierIpAddress", "EnaSrdSpecification", "Ipv6AddressCount", "DeleteOnTermination")
			index, ok := iface["DeviceIndex"].(string)
			if !ok {
				return fmt.Errorf("NetworkInterfaces DeviceIndex must be a string")
			}
			value, err := strconv.ParseInt(index, 10, 32)
			if err != nil || value < 0 {
				return fmt.Errorf("NetworkInterfaces DeviceIndex must be a nonnegative integer string")
			}
			copy["DeviceIndex"] = value
			if groups, found := iface["GroupSet"]; found {
				copy["Groups"] = groups
			}
			interfaces = append(interfaces, copy)
		}
		in["NetworkInterfaces"] = interfaces
	}
	return nil
}

func cfnEC2InstanceMappingsReplace(before, after any) bool {
	strip := func(raw any) any {
		list, ok := raw.([]any)
		if !ok {
			return raw
		}
		out := make([]any, 0, len(list))
		for _, item := range list {
			mapping, ok := cfnComputeObject(item)
			if !ok {
				return raw
			}
			copy := cfnComputeCopy(mapping, "DeviceName", "Ebs", "VirtualName", "NoDevice")
			if ebs, ok := cfnComputeObject(mapping["Ebs"]); ok {
				copy["Ebs"] = cfnComputeCopy(ebs, "SnapshotId", "VolumeSize", "VolumeType", "Iops", "Encrypted", "KmsKeyId", "Throughput")
			}
			out = append(out, copy)
		}
		return out
	}
	return !cfnEC2ComputeEqual(strip(before), strip(after))
}

func (h cfnEC2Instance) mappings(ctx context.Context, r cloudformation.ResourceRequest, v api.Instance) error {
	list, ok := r.Properties["BlockDeviceMappings"].([]any)
	if !ok {
		return nil
	}
	updates := []any{}
	for _, raw := range list {
		mapping, _ := cfnComputeObject(raw)
		ebs, ok := cfnComputeObject(mapping["Ebs"])
		if !ok {
			continue
		}
		value, found := ebs["DeleteOnTermination"]
		if !found {
			continue
		}
		device := cfnComputeString(mapping, "DeviceName")
		matched := false
		for _, live := range v.BlockDeviceMappings {
			if cfnComputeValue(live.DeviceName) != device || live.Ebs == nil {
				continue
			}
			matched = true
			if value != cfnEC2ComputeBool(live.Ebs.DeleteOnTermination) {
				updates = append(updates, map[string]any{"DeviceName": device, "Ebs": map[string]any{"VolumeId": cfnComputeValue(live.Ebs.VolumeId), "DeleteOnTermination": value}})
			}
		}
		if !matched {
			return fmt.Errorf("block device %s is not attached", device)
		}
	}
	if len(updates) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, h.commands, "ec2", "ModifyInstanceAttribute", map[string]any{"InstanceId": r.PhysicalID, "BlockDeviceMappings": updates})
}
