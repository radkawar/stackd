package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

func (h cfnEC2Volume) modify(ctx context.Context, r cloudformation.ResourceRequest, v api.Volume) error {
	actual, err := cfnEC2ComputeProjection(v)
	if err != nil {
		return err
	}
	in := map[string]any{"VolumeId": r.PhysicalID}
	kind := cfnComputeString(r.Properties, "VolumeType")
	if kind == "" {
		kind = "gp2"
	}
	for _, key := range []string{"Size", "Iops", "Throughput", "VolumeType"} {
		if !cfnComputeChanged(r.Previous, r.Properties, key) {
			continue
		}
		value, found := r.Properties[key]
		if !found {
			switch key {
			case "VolumeType":
				value = "gp2"
			case "Iops":
				if kind == "gp3" {
					value = 3000
				} else if kind == "io1" || kind == "io2" {
					return fmt.Errorf("iops is required for %s", kind)
				} else {
					continue
				}
			case "Throughput":
				if kind == "gp3" {
					value = 125
				} else {
					continue
				}
			case "Size":
				continue // AWS does not shrink on removal or rollback.
			}
		}
		if !cfnEC2ComputeEqual(value, actual[key]) {
			in[key] = value
		}
	}
	if len(in) == 1 {
		return nil
	}
	// A command receipt may be lost while the actual owner retains an active
	// modification. Observe its target before issuing any new command.
	out, err := cfnComputeCall[api.DescribeVolumesModificationsResult](ctx, h.commands, "ec2", "DescribeVolumesModifications", map[string]any{"VolumeIds": []string{r.PhysicalID}})
	if err != nil {
		return err
	}
	for _, m := range out.VolumesModifications {
		state := cfnComputeValue(m.ModificationState)
		if state != "modifying" && state != "optimizing" {
			continue
		}
		target, err := cfnEC2ComputeProjection(m)
		if err != nil {
			return err
		}
		for key, value := range in {
			if key == "VolumeId" {
				continue
			}
			if !cfnEC2ComputeEqual(value, target["Target"+key]) {
				return fmt.Errorf("volume has a different modification in progress")
			}
		}
		return nil
	}
	return cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "ModifyVolume", in)
}
