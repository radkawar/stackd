package ebs

import (
	"fmt"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

// volumeConfiguration admits configuration before CreateVolume authorization and
// DryRun. Multi-Attach type support is checked separately after DryRun.
func volumeConfiguration(in *api.CreateVolumeRequest, snapshotSize int64) (VolumeConfiguration, error) {
	out := VolumeConfiguration{Type: api.VolumeType(strings.ToLower(value(in.VolumeType)))}
	if in.VolumeInitializationRate != nil && value(in.SnapshotId) == "" {
		return out, ec2Failure("InvalidParameterCombination", "You can't specify VolumeInitializationRate for volumes that are not created from a snapshot.")
	}
	if in.VolumeInitializationRate != nil && (*in.VolumeInitializationRate < 100 || *in.VolumeInitializationRate > 300) {
		return out, ec2Failure("InvalidParameterValue", "The value specified for VolumeInitializationRate is not in the allowed range.")
	}
	if out.Type == "" {
		out.Type = "gp2"
	}
	minimum, maximum := int32(1), int32(16384)
	switch out.Type {
	case "gp2":
	case "gp3":
		maximum = 65536
	case "standard":
		maximum = 1024
	case "io1":
		minimum = 4
	case "io2":
		minimum, maximum = 4, 65536
	case "sc1", "st1":
		minimum = 125
	default:
		return out, ec2Failure("UnknownVolumeType", "Unsupported volume type '"+string(out.Type)+"' for volume creation. ")
	}
	for _, parameter := range []struct {
		name  string
		value *api.Integer
	}{{"size", in.Size}, {"iops", in.Iops}, {"throughput", in.Throughput}} {
		if parameter.value != nil && *parameter.value < 0 {
			return out, ec2Failure("InvalidParameterValue", fmt.Sprintf("Value (%d) for parameter %s is invalid. Value must be a positive integer.", *parameter.value, parameter.name))
		}
	}
	provisioned := out.Type == "io1" || out.Type == "io2"
	if provisioned && in.Iops == nil {
		return out, ec2Failure("InvalidParameterCombination", "The parameter iops must be specified for "+string(out.Type)+" volumes.")
	}
	if !provisioned && out.Type != "gp3" && in.Iops != nil {
		return out, ec2Failure("InvalidParameterCombination", "The parameter iops is not supported for "+string(out.Type)+" volumes.")
	}
	if out.Type != "gp3" && in.Throughput != nil {
		return out, ec2Failure("InvalidParameterCombination", "The throughput parameter is not supported for "+string(out.Type)+" volumes.")
	}
	size := snapshotSize
	if in.Size != nil {
		size = max(snapshotSize, int64(*in.Size))
	} else if snapshotSize == 0 {
		return out, ec2Failure("MissingParameter", "The request must contain the parameter size/snapshot")
	}
	if size < int64(minimum) {
		return out, ec2Failure("InvalidParameterValue", fmt.Sprintf("The volume size is invalid for %s volumes: %d GiB. %s volumes must be at least %d GiB in size. Please specify a volume size above the minimum limit.", out.Type, size, out.Type, minimum))
	}
	if size > int64(maximum) {
		return out, ec2Failure("InvalidParameterValue", fmt.Sprintf("Volume of %dGiB is too large for volume type %s; maximum is %dGiB", size, out.Type, maximum))
	}
	out.Size = int32(size)
	switch out.Type {
	case "gp2":
		out.Iops = min(16000, max(100, out.Size*3))
	case "gp3", "io1", "io2":
		out.Iops = 3000
		if in.Iops != nil {
			out.Iops = int32(*in.Iops)
		}
		maxIops, ratio := int32(80000), int32(500)
		if out.Type == "io1" {
			maxIops, ratio = 64000, 50
		} else if out.Type == "io2" {
			maxIops, ratio = 256000, 1000
		}
		if out.Iops < 100 {
			return out, ec2Failure("InvalidParameterValue", fmt.Sprintf("Volume iops of %d is too low; minimum is 100.", out.Iops))
		}
		if out.Iops > maxIops {
			return out, ec2Failure("InvalidParameterValue", fmt.Sprintf("Volume iops of %d is too high; maximum is %d.", out.Iops, maxIops))
		}
		if !(out.Type == "gp3" && out.Iops == 3000) && int64(out.Iops) > size*int64(ratio) {
			return out, ec2Failure("InvalidParameterValue", fmt.Sprintf("Iops to volume size ratio of %.6f is too high; maximum is %d", float64(out.Iops)/float64(size), ratio))
		}
		if out.Type == "gp3" {
			out.Iops = max(3000, out.Iops)
		}
	}
	if out.Type == "gp3" {
		out.Throughput = 125
		if in.Throughput != nil {
			out.Throughput = max(125, int32(*in.Throughput))
		}
		if out.Throughput > 2000 {
			return out, ec2Failure("InvalidParameterValue", fmt.Sprintf("Volume throughput of %d is too high; maximum is 2000.", out.Throughput))
		}
		if int64(out.Throughput)*4 > int64(out.Iops) {
			return out, ec2Failure("InvalidParameterValue", fmt.Sprintf("Throughput (MiBps) to iops ratio of %.6f is too high; maximum is 0.250000 MiBps per iops", float64(out.Throughput)/float64(out.Iops)))
		}
	}
	out.MultiAttach = in.MultiAttachEnabled != nil && bool(*in.MultiAttachEnabled)
	return out, nil
}

func volumeMultiAttachConfiguration(configuration VolumeConfiguration) error {
	if configuration.MultiAttach && configuration.Type != "io1" && configuration.Type != "io2" {
		return ec2Failure("InvalidParameterCombination", "The parameter multi-attach-enabled is not supported for "+string(configuration.Type)+" volumes.")
	}
	return nil
}
