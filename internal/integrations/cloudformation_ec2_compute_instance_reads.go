package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

func (h cfnEC2Instance) topology(ctx context.Context, v api.Instance, p cloudformation.Properties) error {
	interfaces := []any{}
	for _, iface := range v.NetworkInterfaces {
		row := map[string]any{"NetworkInterfaceId": cfnComputeValue(iface.NetworkInterfaceId), "SubnetId": cfnComputeValue(iface.SubnetId), "PrivateIpAddress": cfnComputeValue(iface.PrivateIpAddress), "Description": cfnComputeValue(iface.Description)}
		if iface.Attachment != nil {
			if iface.Attachment.DeviceIndex != nil {
				row["DeviceIndex"] = fmt.Sprint(*iface.Attachment.DeviceIndex)
			}
			if iface.Attachment.DeleteOnTermination != nil {
				row["DeleteOnTermination"] = cfnEC2ComputeBool(iface.Attachment.DeleteOnTermination)
			}
		}
		groups := []any{}
		for _, g := range iface.Groups {
			groups = append(groups, cfnComputeValue(g.GroupId))
		}
		row["GroupSet"] = groups
		addresses := []any{}
		for _, a := range iface.PrivateIpAddresses {
			addresses = append(addresses, map[string]any{"PrivateIpAddress": cfnComputeValue(a.PrivateIpAddress), "Primary": cfnEC2ComputeBool(a.Primary)})
		}
		row["PrivateIpAddresses"] = addresses
		if len(iface.Ipv6Addresses) > 0 {
			addresses := []any{}
			for _, a := range iface.Ipv6Addresses {
				addresses = append(addresses, map[string]any{"Ipv6Address": cfnComputeValue(a.Ipv6Address)})
			}
			row["Ipv6Addresses"] = addresses
		}
		interfaces = append(interfaces, row)
	}
	p["NetworkInterfaces"] = interfaces
	volumes, mappings := []any{}, []any{}
	for _, mapping := range v.BlockDeviceMappings {
		if mapping.Ebs == nil {
			continue
		}
		id := cfnComputeValue(mapping.Ebs.VolumeId)
		volume, err := cfnEC2Volume(h).get(ctx, id)
		if err != nil {
			return err
		}
		live, err := cfnEC2ComputeProjection(volume)
		if err != nil {
			return err
		}
		ebs := cfnComputeCopy(live, "SnapshotId", "VolumeType", "KmsKeyId", "Encrypted", "Iops")
		if volume.Size != nil {
			ebs["VolumeSize"] = int64(*volume.Size)
		}
		ebs["DeleteOnTermination"] = cfnEC2ComputeBool(mapping.Ebs.DeleteOnTermination)
		device := cfnComputeValue(mapping.DeviceName)
		volumes = append(volumes, map[string]any{"VolumeId": id, "Device": device})
		mappings = append(mappings, map[string]any{"DeviceName": device, "Ebs": ebs})
	}
	p["Volumes"], p["BlockDeviceMappings"] = volumes, mappings
	return nil
}
