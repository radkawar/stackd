package ebs

import (
	"context"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
)

func (s *Service) DeleteVolume(ctx context.Context, in *api.DeleteVolumeRequest) (*api.Unit, error) {
	// DeleteVolume validates identifiers and existence before IAM and DryRun,
	// unlike the attribute and Elastic Volumes controls.
	if in.VolumeId == nil {
		return nil, ec2Failure("MissingParameter", "The request must include the VolumeId parameter. Add the required parameter and retry the request.")
	}
	if !validControlVolumeID(string(*in.VolumeId)) {
		return nil, ec2Failure("InvalidParameterValue", "The volume ID '"+string(*in.VolumeId)+"' is malformed")
	}
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := ownedVolume(tx, string(*in.VolumeId))
		if err != nil {
			return err
		}
		if v.Status == api.VolumeStateDeleting {
			return volumeMissing(v.Key.ID)
		}
		if err := s.authorizeVolume(tx.Context(), "DeleteVolume", v, nil); err != nil {
			return err
		}
		if err := ec2DryRun(in.DryRun); err != nil {
			return err
		}
		if err := volumeMutationFence(tx.Context(), v); err != nil {
			return err
		}
		attachments, err := s.volumeAttachments(tx.Context(), v)
		if err != nil {
			return err
		}
		if len(attachments) > 0 {
			return ec2Failure("VolumeInUse", "Volume "+v.Key.ID+" is currently in-use.")
		}
		v.Status = api.VolumeStateDeleting
		v.TransitionAt = s.clock.Now().Add(VolumeDeletionDelay)
		v.RequestID = awsctx.FromContext(tx.Context()).RequestID
		v.ParentEventID = apievents.EventID(tx.Context())
		v.Modification = nil
		if err := tx.PutVolume(v); err != nil {
			return err
		}
		return ec2.RecordExternalSuccess(tx.Context(), &api.Unit{})
	})
	if err != nil {
		return nil, err
	}
	s.jobs.Wake()
	return &api.Unit{}, nil
}
