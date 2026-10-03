package ebs

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/apievents"
	ebsapi "stackd/internal/awsapi/ebs"
	api "stackd/internal/awsapi/ec2"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
)

func instanceVolumeRequest(e *api.EbsBlockDevice) api.CreateVolumeRequest {
	return api.CreateVolumeRequest{Size: e.VolumeSize, VolumeType: e.VolumeType, Iops: e.Iops, Throughput: e.Throughput, SnapshotId: e.SnapshotId, Encrypted: e.Encrypted, KmsKeyId: (*api.KmsKeyId)(e.KmsKeyId), VolumeInitializationRate: e.VolumeInitializationRate}
}

func mergeInstanceEBS(base, override *api.EbsBlockDevice) *api.EbsBlockDevice {
	if base == nil {
		base = &api.EbsBlockDevice{}
	}
	out := *base
	if override == nil {
		return &out
	}
	if override.VolumeType != nil && value(override.VolumeType) != value(base.VolumeType) {
		out.Iops, out.Throughput = nil, nil
	}
	if override.AvailabilityZone != nil {
		out.AvailabilityZone = override.AvailabilityZone
	}
	if override.AvailabilityZoneId != nil {
		out.AvailabilityZoneId = override.AvailabilityZoneId
	}
	if override.DeleteOnTermination != nil {
		out.DeleteOnTermination = override.DeleteOnTermination
	}
	if override.EbsCardIndex != nil {
		out.EbsCardIndex = override.EbsCardIndex
	}
	if override.Encrypted != nil {
		out.Encrypted = override.Encrypted
	}
	if override.Iops != nil {
		out.Iops = override.Iops
	}
	if override.KmsKeyId != nil {
		out.KmsKeyId = override.KmsKeyId
	}
	if override.OutpostArn != nil {
		out.OutpostArn = override.OutpostArn
	}
	if override.SnapshotId != nil {
		out.SnapshotId = override.SnapshotId
	}
	if override.Throughput != nil {
		out.Throughput = override.Throughput
	}
	if override.VolumeInitializationRate != nil {
		out.VolumeInitializationRate = override.VolumeInitializationRate
	}
	if override.VolumeSize != nil {
		out.VolumeSize = override.VolumeSize
	}
	if override.VolumeType != nil {
		out.VolumeType = override.VolumeType
	}
	return &out
}

func (s *Service) instanceSnapshot(r Reader, id string) (*SnapshotRecord, error) {
	if id == "" {
		return nil, nil
	}
	if err := snapshotControlID(id, false); err != nil {
		return nil, err
	}
	scope := scopeFor(r.Context())
	v, err := r.RegionalSnapshot(scope.Partition, scope.Region, id)
	if errors.Is(err, ErrNotFound) {
		return nil, ec2Failure("InvalidSnapshot.NotFound", "Snapshot does not exist")
	}
	if err != nil {
		return nil, err
	}
	visible, err := s.ec2Visible(r, v)
	if err != nil {
		return nil, err
	}
	if !visible || v.Deleted {
		return nil, ec2Failure("InvalidSnapshot.NotFound", "Snapshot does not exist")
	}
	if v.Status != ebsapi.StatusCOMPLETED {
		return nil, ec2Failure("IncorrectState", "Snapshot is in invalid state - "+string(v.Status))
	}
	s.observeSnapshot(r.Context(), v)
	return &v, nil
}

// PlanInstanceVolumes resolves the image's device defaults before EC2 evaluates
// RunInstances. It neither allocates volumes nor invokes CreateVolume IAM.
func (s *Service) PlanInstanceVolumes(ctx context.Context, image api.Image, overrides api.BlockDeviceMappingRequestList, zone ec2.AvailabilityZone) (api.BlockDeviceMappingRequestList, error) {
	planned := make(api.BlockDeviceMappingRequestList, 0, len(image.BlockDeviceMappings)+len(overrides))
	indexes := make(map[string]int, len(image.BlockDeviceMappings))
	for _, mapping := range image.BlockDeviceMappings {
		if mapping.Ebs != nil {
			mapping.Ebs = mergeInstanceEBS(mapping.Ebs, nil)
		}
		if mapping.Ebs != nil && value(mapping.Ebs.VolumeType) != "gp3" && value(mapping.Ebs.VolumeType) != "io1" && value(mapping.Ebs.VolumeType) != "io2" {
			mapping.Ebs.Iops = nil
		}
		indexes[value(mapping.DeviceName)] = len(planned)
		planned = append(planned, mapping)
	}
	seen := make(map[string]bool, len(overrides))
	for _, override := range overrides {
		name := value(override.DeviceName)
		if name == "" || seen[name] {
			return nil, ec2Failure("InvalidBlockDeviceMapping", "Device names must be present and unique.")
		}
		seen[name] = true
		if override.NoDevice != nil && (override.Ebs != nil || override.VirtualName != nil) {
			return nil, ec2Failure("InvalidBlockDeviceMapping", "NoDevice cannot be combined with Ebs or VirtualName.")
		}
		i, ok := indexes[name]
		if !ok {
			i = len(planned)
			indexes[name] = i
			planned = append(planned, api.BlockDeviceMapping{DeviceName: override.DeviceName})
		}
		if override.NoDevice != nil || override.VirtualName != nil {
			planned[i] = override
			continue
		}
		planned[i].Ebs = mergeInstanceEBS(planned[i].Ebs, override.Ebs)
		planned[i].NoDevice, planned[i].VirtualName = nil, nil
	}
	err := s.repository.View(ctx, func(r Reader) error {
		defaults, err := s.encryptionDefault(r)
		if err != nil {
			return err
		}
		for i := range planned {
			mapping := &planned[i]
			if mapping.NoDevice != nil {
				if value(mapping.DeviceName) == value(image.RootDeviceName) {
					return ec2Failure("InvalidBlockDeviceMapping", "The root device cannot be suppressed.")
				}
				continue
			}
			if mapping.VirtualName != nil {
				return ec2Failure("UnsupportedOperation", "Native instance-store disks are not configured.")
			}
			e := mapping.Ebs
			if e == nil {
				return ec2Failure("InvalidBlockDeviceMapping", "An EBS mapping requires Ebs parameters.")
			}
			if e.OutpostArn != nil || e.EbsCardIndex != nil && *e.EbsCardIndex != 0 {
				return ec2Failure("UnsupportedOperation", "The requested EBS placement is not supported by the native backend.")
			}
			if e.AvailabilityZone != nil && value(e.AvailabilityZone) != zone.Name || e.AvailabilityZoneId != nil && value(e.AvailabilityZoneId) != zone.ID {
				return ec2Failure("InvalidParameterValue", "The volume and instance Availability Zones must match.")
			}
			source, err := s.instanceSnapshot(r, value(e.SnapshotId))
			if err != nil {
				return err
			}
			var sourceSize int64
			if source != nil {
				sourceSize = source.VolumeSize
			}
			if e.VolumeSize != nil && int64(*e.VolumeSize) < sourceSize {
				return ec2Failure("InvalidBlockDeviceMapping", "Volume size cannot be smaller than the source snapshot.")
			}
			if e.Encrypted != nil && !bool(*e.Encrypted) && source != nil && source.KMSKeyARN != "" {
				return ec2Failure("InvalidParameterCombination", "Encrypted snapshots must be used to create encrypted volumes.")
			}
			if e.KmsKeyId != nil && (e.Encrypted == nil || !bool(*e.Encrypted)) {
				return ec2Failure("InvalidParameterDependency", "The parameter KmsKeyId requires the parameter Encrypted to be set.")
			}
			request := instanceVolumeRequest(e)
			configuration, err := volumeConfiguration(&request, sourceSize)
			if err != nil {
				return err
			}
			e.VolumeSize, e.VolumeType = new(api.Integer(configuration.Size)), new(configuration.Type)
			if configuration.Type == "gp3" || configuration.Type == "io1" || configuration.Type == "io2" {
				e.Iops = new(api.Integer(configuration.Iops))
			}
			if configuration.Type == "gp3" {
				e.Throughput = new(api.Integer(configuration.Throughput))
			}
			encrypted := defaults.Enabled || source != nil && source.KMSKeyARN != "" || e.Encrypted != nil && bool(*e.Encrypted)
			e.Encrypted = new(api.Boolean(encrypted))
			if encrypted && value(e.KmsKeyId) == "" {
				keyID := defaults.KMSKeyID
				if source != nil && source.Key.AccountID == scopeFor(ctx).AccountID && source.KMSKeyARN != "" {
					keyID = source.KMSKeyARN
				}
				e.KmsKeyId = new(api.String(keyID))
			}
			if e.DeleteOnTermination == nil {
				e.DeleteOnTermination = new(api.Boolean(true))
			}
		}
		return nil
	})
	return planned, err
}

func (s *Service) AdmitInstanceVolumes(ctx context.Context, instanceID string, zone ec2.AvailabilityZone, plan api.BlockDeviceMappingRequestList, tags api.TagList) (api.InstanceBlockDeviceMappingList, error) {
	out := make(api.InstanceBlockDeviceMappingList, 0, len(plan))
	err := s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		scope := scopeFor(ctx)
		for _, mapping := range plan {
			if mapping.NoDevice != nil {
				continue
			}
			if mapping.Ebs == nil {
				return ec2Failure("InvalidBlockDeviceMapping", "Missing EBS mapping.")
			}
			source, err := s.instanceSnapshot(tx, value(mapping.Ebs.SnapshotId))
			if err != nil {
				return err
			}
			request := instanceVolumeRequest(mapping.Ebs)
			var sourceSize int64
			if source != nil {
				sourceSize = source.VolumeSize
			}
			configuration, err := volumeConfiguration(&request, sourceSize)
			if err != nil {
				return err
			}
			id, err := tx.NextVolumeID(scope)
			if err != nil {
				return err
			}
			now := s.clock.Now()
			v := VolumeRecord{Key: VolumeKey{Scope: scope, ID: id}, Configuration: configuration, ZoneName: zone.Name, ZoneID: zone.ID, Created: now, TransitionAt: now.Add(VolumeCreationDelay), Status: api.VolumeStateCreating, Encrypted: mapping.Ebs.Encrypted != nil && bool(*mapping.Ebs.Encrypted), LineageID: id, CreationInput: request, InitializationRate: int32(number(mapping.Ebs.VolumeInitializationRate)), Tags: make(map[string]string, len(tags)), RequestID: awsctx.FromContext(ctx).RequestID, ParentEventID: apievents.EventID(ctx)}
			for _, tag := range tags {
				v.Tags[value(tag.Key)] = value(tag.Value)
			}
			if source != nil {
				v.SnapshotID, v.LineageID = source.Key.ID, source.LineageID
			}
			if err := tx.PutVolume(v); err != nil {
				return err
			}
			var material BlockKeyMaterial
			if v.Encrypted {
				if s.instanceKeys == nil || s.ec2Keys == nil {
					return errors.New("instance EBS encryption is not configured")
				}
				keyID := value(mapping.Ebs.KmsKeyId)
				var rejected *awswire.Error
				if keyID == "" || keyID == "alias/aws/ebs" {
					keyID, rejected = s.ec2Keys.EnsureServiceKey(ctx, "ebs")
				}
				if strings.HasPrefix(keyID, "arn:") {
					v.KMSKeyARN = keyID
				}
				if rejected == nil {
					var grantID string
					var grant *kmsapi.CreateGrantOutput
					var rejection *awswire.Error
					material, grant, rejection = s.instanceKeys.PrepareInstanceVolume(ctx, source, v, keyID)
					if grant != nil {
						grantID = value(grant.GrantId)
					}
					v.ServiceGrantID = kmsapi.GrantIdType(grantID)
					v.KMSKeyARN, v.WrappedKey = material.KMSKeyARN, material.WrappedKey
					if v.KMSKeyARN == "" {
						v.KMSKeyARN = keyID
					}
					rejected = rejection
					clear(material.SourcePlaintext)
					clear(material.DestinationPlaintext)
				}
				if rejected == nil {
					grant, rejection := s.instanceKeys.StartInstanceVolume(ctx, v, instanceID)
					if grant != nil {
						v.InfrastructureGrantID = kmsapi.GrantIdType(value(grant.GrantId))
					}
					rejected = rejection
				}
				if rejected != nil {
					v.StateMessage = rejected.Code + ": " + rejected.Message
				}
			}
			if v.StateMessage == "" && source != nil {
				v.Creation = &VolumeCreation{
					Source: source.Key, SourceWrappedKey: material.SourceWrappedKey,
					ReuseSourceCiphertext: material.ReuseSourceCiphertext,
				}
			}
			if err := tx.PutVolume(v); err != nil {
				return err
			}
			out = append(out, api.InstanceBlockDeviceMapping{DeviceName: mapping.DeviceName, Ebs: &api.EbsInstanceBlockDevice{VolumeId: new(api.String(id)), AttachTime: new(now), DeleteOnTermination: mapping.Ebs.DeleteOnTermination, EbsCardIndex: mapping.Ebs.EbsCardIndex, Status: new(api.AttachmentStatusAttaching)}})
		}
		return nil
	})
	if err == nil {
		s.jobs.Wake()
	}
	return out, err
}

// AdmitInstanceVolumeStart runs in StartInstances' caller transaction. KMS
// rejection is retained for the asynchronous state machine, not returned as a
// synchronous launch error.
func (s *Service) AdmitInstanceVolumeStart(ctx context.Context, instance api.Instance) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		for _, mapping := range instance.BlockDeviceMappings {
			if mapping.Ebs == nil || value(mapping.Ebs.Status) == "detached" || value(mapping.Ebs.Status) == "detaching" {
				continue
			}
			v, err := ownedVolume(tx, value(mapping.Ebs.VolumeId))
			if err != nil {
				return err
			}
			if !v.Encrypted {
				continue
			}
			if s.instanceKeys == nil {
				return errors.New("instance EBS encryption is not configured")
			}
			if v.InfrastructureGrantID != "" {
				if rejected := s.instanceKeys.RetireInstanceVolumeGrant(tx.Context(), v, v.InfrastructureGrantID); rejected != nil {
					return rejected
				}
				v.InfrastructureGrantID = ""
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
				grant, failure := s.instanceKeys.StartInstanceVolume(tx.Context(), v, value(instance.InstanceId))
				if grant != nil {
					v.InfrastructureGrantID = kmsapi.GrantIdType(value(grant.GrantId))
				}
				rejected = failure
			}
			v.StateMessage = ""
			if rejected != nil {
				v.StateMessage = rejected.Code + ": " + rejected.Message
			}
			if err := tx.PutVolume(v); err != nil {
				return err
			}
		}
		return nil
	})
}

var _ ec2.InstanceVolumes = (*Service)(nil)
