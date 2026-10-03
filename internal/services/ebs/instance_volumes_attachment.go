package ebs

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/ec2"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

// AdmitInstanceVolumeAttachment joins AttachVolume's caller transaction. EC2
// authorizes and owns the relationship; EBS admits only disk and KMS state.
func (s *Service) AdmitInstanceVolumeAttachment(ctx context.Context, instance api.Instance, mapping api.InstanceBlockDeviceMapping) error {
	if mapping.Ebs == nil {
		return ec2Failure("InvalidParameterValue", "An EBS volume mapping is required.")
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		v, err := ownedVolume(tx, value(mapping.Ebs.VolumeId))
		if err != nil {
			return err
		}
		if instance.Placement == nil || value(instance.Placement.AvailabilityZone) != v.ZoneName {
			return ec2Failure("InvalidVolume.ZoneMismatch", "The volume and instance must be in the same Availability Zone.")
		}
		if v.Status != api.VolumeStateAvailable {
			return ec2Failure("IncorrectState", "Volume is not in the available state.")
		}
		attachments, err := s.volumeAttachments(tx.Context(), v)
		if err != nil {
			return err
		}
		if len(attachments) != 0 {
			return ec2Failure("VolumeInUse", "Volume "+v.Key.ID+" is currently in-use.")
		}
		if v.Configuration.MultiAttach {
			return ec2Failure("UnsupportedOperation", "Native shared-writer EBS Multi-Attach is not supported.")
		}
		if !v.Encrypted {
			return nil
		}
		if s.instanceKeys == nil {
			return errors.New("instance EBS encryption is not configured")
		}
		var rejected *awswire.Error
		if v.ServiceGrantID == "" {
			grant, failure := s.instanceKeys.AdoptInstanceVolume(tx.Context(), v)
			if grant != nil {
				v.ServiceGrantID = kmsapi.GrantIdType(value(grant.GrantId))
			}
			rejected = failure
		}
		if rejected == nil {
			if err := s.retireInfrastructureGrant(tx.Context(), &v); err != nil {
				return err
			}
			if instance.State == nil || value(instance.State.Name) != "stopped" {
				grant, failure := s.instanceKeys.StartInstanceVolume(tx.Context(), v, value(instance.InstanceId))
				if grant != nil {
					v.InfrastructureGrantID = kmsapi.GrantIdType(value(grant.GrantId))
				}
				rejected = failure
			}
		}
		v.StateMessage = ""
		if rejected != nil {
			v.StateMessage = rejected.Code + ": " + rejected.Message
		}
		return tx.PutVolume(v)
	})
}
