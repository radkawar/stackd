package ebs

import (
	"context"

	api "stackd/internal/awsapi/ec2"
)

// InstanceLaunchMappings reads actual attached-volume state and enforces the
// GetLaunchTemplateData dependency's current DescribeVolumes permission.
func (s *Service) InstanceLaunchMappings(ctx context.Context, instance api.Instance) (api.BlockDeviceMappingRequestList, error) {
	out := api.BlockDeviceMappingRequestList{}
	err := s.repository.View(ctx, func(tx Reader) error {
		if len(instance.BlockDeviceMappings) > 0 {
			if err := s.authorizeVolume(tx.Context(), "DescribeVolumes", VolumeRecord{}, nil); err != nil {
				return err
			}
		}
		for _, attached := range instance.BlockDeviceMappings {
			if attached.Ebs == nil || value(attached.Ebs.Status) == "detached" {
				continue
			}
			volume, err := tx.Volume(VolumeKey{Scope: scopeFor(ctx), ID: value(attached.Ebs.VolumeId)})
			if err != nil {
				return err
			}
			ebs := &api.EbsBlockDevice{DeleteOnTermination: attached.Ebs.DeleteOnTermination, Encrypted: new(api.Boolean(volume.Encrypted)), VolumeSize: new(api.Integer(volume.Configuration.Size)), VolumeType: new(volume.Configuration.Type)}
			if volume.KMSKeyARN != "" {
				ebs.KmsKeyId = new(api.String(volume.KMSKeyARN))
			}
			if volume.SnapshotID != "" {
				ebs.SnapshotId = new(api.SnapshotId(volume.SnapshotID))
			}
			if volume.Configuration.Iops != 0 {
				ebs.Iops = new(api.Integer(volume.Configuration.Iops))
			}
			if volume.Configuration.Throughput != 0 {
				ebs.Throughput = new(api.Integer(volume.Configuration.Throughput))
			}
			out = append(out, api.BlockDeviceMapping{DeviceName: attached.DeviceName, Ebs: ebs})
		}
		return nil
	})
	return out, err
}
