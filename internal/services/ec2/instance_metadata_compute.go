package ec2

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

func instanceComputeMetadata(r InstanceRecord, item string) ([]byte, string, int) {
	value, present := instanceComputeMetadataValue(r, item)
	if !present {
		return nil, "", http.StatusNotFound
	}
	return metadataText(value)
}

func instanceComputeMetadataValue(r InstanceRecord, item string) (string, bool) {
	d := r.Data
	value := ""
	switch item {
	case "instance-id":
		return r.Key.ID, true
	case "ami-id":
		value = str(d.ImageId)
	case "ami-launch-index":
		if d.AmiLaunchIndex != nil {
			return strconv.Itoa(int(*d.AmiLaunchIndex)), true
		}
	case "ami-manifest-path":
		if str(d.RootDeviceType) == "ebs" {
			return "(unknown)", true
		}
	case "profile":
		if str(d.VirtualizationType) == "hvm" {
			return "default-hvm", true
		}
	case "instance-action":
		// This is the legacy AMI bundling signal, not StopInstances or reboot.
		// The HVM/EBS owner has no bundling transition.
		if str(d.RootDeviceType) == "ebs" {
			return "none", true
		}
	case "instance-life-cycle":
		value = str(d.InstanceLifecycle)
		if value == "" {
			return "on-demand", true
		}
	case "instance-type":
		value = str(d.InstanceType)
	case "reservation-id":
		value = r.ReservationID
	case "kernel-id":
		value = str(d.KernelId)
	case "ramdisk-id":
		value = str(d.RamdiskId)
	case "product-codes":
		codes := make([]string, 0, len(d.ProductCodes))
		for _, product := range d.ProductCodes {
			if str(product.ProductCodeType) == "marketplace" {
				codes = append(codes, str(product.ProductCodeId))
			}
		}
		value = strings.Join(codes, "\n")
	case "local-ipv4":
		value = str(d.PrivateIpAddress)
	case "hostname", "local-hostname":
		value = str(d.PrivateDnsName)
	case "public-ipv4":
		value = str(d.PublicIpAddress)
	case "public-hostname":
		value = str(d.PublicDnsName)
	case "mac":
		for _, eni := range d.NetworkInterfaces {
			if eni.Attachment != nil && eni.Attachment.DeviceIndex != nil && *eni.Attachment.DeviceIndex == 0 {
				value = str(eni.MacAddress)
				break
			}
		}
	case "security-groups":
		names := make([]string, 0, len(d.SecurityGroups))
		for _, group := range d.SecurityGroups {
			names = append(names, str(group.GroupName))
		}
		value = strings.Join(names, "\n")
	}
	return value, value != ""
}

func instancePlacementMetadata(r InstanceRecord, version, item string) ([]byte, string, int) {
	placement := r.Data.Placement
	if placement == nil {
		return nil, "", http.StatusNotFound
	}
	if item == "placement" {
		names := []string{"region"}
		if str(placement.AvailabilityZone) != "" {
			names = append(names, "availability-zone")
		}
		if str(placement.AvailabilityZoneId) != "" {
			names = append(names, "availability-zone-id")
		}
		if str(placement.GroupName) != "" {
			names = append(names, "group-name")
		}
		if str(placement.HostId) != "" {
			names = append(names, "host-id")
		}
		if placement.PartitionNumber != nil {
			names = append(names, "partition-number")
		}
		return metadataDirectory(version, "meta-data/placement/", names)
	}
	value := ""
	switch item {
	case "placement/availability-zone":
		value = str(placement.AvailabilityZone)
	case "placement/availability-zone-id":
		value = str(placement.AvailabilityZoneId)
	case "placement/region":
		value = r.Key.Scope.Region
	case "placement/group-name":
		value = str(placement.GroupName)
	case "placement/host-id":
		value = str(placement.HostId)
	case "placement/partition-number":
		if placement.PartitionNumber != nil {
			value = strconv.Itoa(int(*placement.PartitionNumber))
		}
	}
	if value == "" {
		return nil, "", http.StatusNotFound
	}
	return metadataText(value)
}

func instanceServicesMetadata(r InstanceRecord, version, item string) ([]byte, string, int) {
	// The current instance-type and execution owner admits commercial us-east-1.
	if r.Key.Scope.Partition != "aws" {
		return nil, "", http.StatusNotFound
	}
	switch item {
	case "services":
		return metadataDirectory(version, "meta-data/services/", []string{"domain", "partition"})
	case "services/domain":
		return metadataText("amazonaws.com")
	case "services/partition":
		return metadataText(r.Key.Scope.Partition)
	}
	return nil, "", http.StatusNotFound
}

func instanceSystemMetadata(ctx context.Context, r InstanceRecord, item string) ([]byte, string, int) {
	if item == "system" {
		if hypervisor := instanceMetadataHypervisor(ctx, r); hypervisor != "" {
			return metadataText(hypervisor)
		}
	}
	return nil, "", http.StatusNotFound
}

func instanceMetadataHypervisor(ctx context.Context, r InstanceRecord) string {
	if instanceTypeRegion(ctx) != nil || r.Data.InstanceType == nil {
		return ""
	}
	return str(capturedInstanceTypes.Types[*r.Data.InstanceType].Hypervisor)
}
