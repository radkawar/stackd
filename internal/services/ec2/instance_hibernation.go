package ec2

import (
	"errors"

	api "stackd/internal/awsapi/ec2"
)

// ErrInstanceHibernationNotReady distinguishes the native transient admission
// error for in-process consumers without changing its AWS protocol code.
var ErrInstanceHibernationNotReady = errors.New("instance is not ready to hibernate")

// admitInstanceHibernation uses the resolved EBS plan, including snapshot and
// regional encryption defaults. Guest kernel/agent support remains an image
// prerequisite, just as on AWS; failed guest hibernation uses normal shutdown.
func admitInstanceHibernation(image api.Image, typ api.InstanceTypeInfo, plan api.BlockDeviceMappingRequestList) error {
	if typ.HibernationSupported == nil || !bool(*typ.HibernationSupported) || (typ.BareMetal != nil && bool(*typ.BareMetal)) {
		return failure("UnsupportedHibernationConfiguration", "The requested instance type does not support hibernation.")
	}
	if str(image.RootDeviceType) != "ebs" || str(image.VirtualizationType) != "hvm" {
		return failure("UnsupportedHibernationConfiguration", "Hibernation requires an EBS-backed HVM image.")
	}
	if typ.MemoryInfo == nil || typ.MemoryInfo.SizeInMiB == nil || *typ.MemoryInfo.SizeInMiB >= 150*1024 {
		return failure("UnsupportedHibernationConfiguration", "Linux instance hibernation requires less than 150 GiB of memory.")
	}
	for _, mapping := range plan {
		if str(mapping.DeviceName) != str(image.RootDeviceName) {
			continue
		}
		if mapping.Ebs == nil || !boolValue(mapping.Ebs.Encrypted) {
			return failure("UnsupportedHibernationConfiguration", "For hibernation, the root device volume must be encrypted.")
		}
		switch str(mapping.Ebs.VolumeType) {
		case "gp2", "gp3", "io1", "io2":
		default:
			return failure("UnsupportedHibernationConfiguration", "Hibernation requires an SSD root volume.")
		}
		if mapping.Ebs.VolumeSize == nil || int64(*mapping.Ebs.VolumeSize)*1024 <= int64(*typ.MemoryInfo.SizeInMiB) {
			return failure("UnsupportedHibernationConfiguration", "The root volume must have space for the operating system and instance memory.")
		}
		return nil
	}
	return failure("UnsupportedHibernationConfiguration", "Hibernation requires an encrypted EBS root volume.")
}
