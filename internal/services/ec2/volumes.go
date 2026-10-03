package ec2

import (
	"context"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
)

// VolumeControl is EC2's consumer boundary to the authoritative EBS disk owner.
// The lazy zone catalog preserves EC2's account-specific physical zone mapping.
// Tag accessors join the caller's transaction, without a second metadata catalog.
type VolumeControl interface {
	CreateVolume(context.Context, *api.CreateVolumeRequest, func(context.Context) (api.AvailabilityZoneList, error)) (*api.Volume, error)
	DescribeVolumes(context.Context, *api.DescribeVolumesRequest) (*api.DescribeVolumesResult, error)
	DeleteVolume(context.Context, *api.DeleteVolumeRequest) (*api.Unit, error)
	ModifyVolume(context.Context, *api.ModifyVolumeRequest) (*api.ModifyVolumeResult, error)
	DescribeVolumesModifications(context.Context, *api.DescribeVolumesModificationsRequest) (*api.DescribeVolumesModificationsResult, error)
	DescribeVolumeAttribute(context.Context, *api.DescribeVolumeAttributeRequest) (*api.DescribeVolumeAttributeResult, error)
	ModifyVolumeAttribute(context.Context, *api.ModifyVolumeAttributeRequest) (*api.Unit, error)
	DescribeVolumeStatus(context.Context, *api.DescribeVolumeStatusRequest) (*api.DescribeVolumeStatusResult, error)
	EnableVolumeIO(context.Context, *api.EnableVolumeIORequest) (*api.Unit, error)
	CreateSnapshot(context.Context, *api.CreateSnapshotRequest) (*api.Snapshot, error)
	VolumeTags(ctx context.Context, action, id string) (api.TagList, authorization.Request, error)
	SetVolumeTags(context.Context, string, api.TagList) error
	ListVolumeTags(context.Context) (api.TagDescriptionList, error)
}

func registerVolumes(s *Service) {
	if s.volumes == nil {
		return
	}
	register(s, "CreateVolume", func(ctx context.Context, _ Transaction, in *api.CreateVolumeRequest) (*api.Volume, error) {
		return s.volumes.CreateVolume(ctx, in, s.availableZones)
	})
	registerOwnedCommand(s, "DescribeVolumes", s.volumes.DescribeVolumes)
	registerExternalOwnedCommand(s, "DeleteVolume", s.volumes.DeleteVolume)
	registerExternalOwnedCommand(s, "ModifyVolume", s.volumes.ModifyVolume)
	registerOwnedCommand(s, "DescribeVolumesModifications", s.volumes.DescribeVolumesModifications)
	registerOwnedCommand(s, "DescribeVolumeAttribute", s.volumes.DescribeVolumeAttribute)
	registerOwnedCommand(s, "ModifyVolumeAttribute", s.volumes.ModifyVolumeAttribute)
	registerOwnedCommand(s, "DescribeVolumeStatus", s.volumes.DescribeVolumeStatus)
	registerOwnedCommand(s, "EnableVolumeIO", s.volumes.EnableVolumeIO)
	registerExternalOwnedCommand(s, "CreateSnapshot", s.volumes.CreateSnapshot)
}
