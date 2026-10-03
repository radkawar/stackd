package ebs

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/ec2"
)

var _ ec2.InstanceImageSnapshots = (*Service)(nil)

// AdmitImageSnapshots joins the image admission transaction. It stores only
// current volume relationships; the image owner fixes native capture timing.
func (s *Service) AdmitImageSnapshots(ctx context.Context, instance api.Instance, imageID string, overrides api.BlockDeviceMappingRequestList, tags api.TagList) (api.BlockDeviceMappingList, error) {
	out := api.BlockDeviceMappingList{}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		requested := make(map[string]api.BlockDeviceMapping, len(overrides))
		for _, mapping := range overrides {
			device := value(mapping.DeviceName)
			if device == "" {
				return ec2Failure("InvalidBlockDeviceMapping", "DeviceName must be specified.")
			}
			if _, ok := requested[device]; ok {
				return ec2Failure("InvalidBlockDeviceMapping", "Device names must be unique.")
			}
			if mapping.VirtualName != nil {
				return ec2Failure("UnsupportedOperation", "Instance-store image mappings are not supported.")
			}
			if mapping.NoDevice != nil && mapping.Ebs != nil {
				return ec2Failure("InvalidBlockDeviceMapping", "NoDevice and Ebs cannot be specified together.")
			}
			if e := mapping.Ebs; e != nil {
				if e.VolumeSize != nil || e.VolumeType != nil || e.Iops != nil || e.Throughput != nil || e.Encrypted != nil || e.KmsKeyId != nil || e.SnapshotId != nil || e.OutpostArn != nil || e.AvailabilityZone != nil || e.AvailabilityZoneId != nil || e.EbsCardIndex != nil || e.VolumeInitializationRate != nil {
					return ec2Failure("InvalidBlockDeviceMapping", "CreateImage can change only DeleteOnTermination on existing EBS mappings.")
				}
			}
			requested[device] = mapping
		}
		rootFound := false
		for _, attached := range instance.BlockDeviceMappings {
			if attached.Ebs == nil {
				continue
			}
			device := value(attached.DeviceName)
			mapping, changed := requested[device]
			delete(requested, device)
			if changed && mapping.NoDevice != nil {
				if device == value(instance.RootDeviceName) {
					return ec2Failure("InvalidBlockDeviceMapping", "The root device cannot be excluded from the image.")
				}
				continue
			}
			if value(attached.Ebs.Status) != "attached" {
				return ec2Failure("IncorrectState", "All image volumes must be attached before creating an image.")
			}
			source, err := tx.Volume(VolumeKey{Scope: scopeFor(ctx), ID: value(attached.Ebs.VolumeId)})
			if err != nil {
				return err
			}
			if err := s.authorizeVolumeSnapshot(tx.Context(), source, tags, "CreateImage"); err != nil {
				return err
			}
			snapshot, err := s.admitVolumeSnapshot(tx, source, tags, "Created by CreateImage("+value(instance.InstanceId)+") for "+imageID, false)
			if err != nil {
				return err
			}
			deleteOnTermination := attached.Ebs.DeleteOnTermination
			if changed && mapping.Ebs != nil && mapping.Ebs.DeleteOnTermination != nil {
				deleteOnTermination = mapping.Ebs.DeleteOnTermination
			}
			ebs := &api.EbsBlockDevice{SnapshotId: new(api.SnapshotId(snapshot.Key.ID)), VolumeSize: new(api.Integer(source.Configuration.Size)), VolumeType: new(source.Configuration.Type), DeleteOnTermination: deleteOnTermination, Encrypted: new(api.Boolean(source.Encrypted))}
			if source.Configuration.Iops != 0 {
				ebs.Iops = new(api.Integer(source.Configuration.Iops))
			}
			if source.Configuration.Throughput != 0 {
				ebs.Throughput = new(api.Integer(source.Configuration.Throughput))
			}
			out = append(out, api.BlockDeviceMapping{DeviceName: new(api.String(device)), Ebs: ebs})
			rootFound = rootFound || device == value(instance.RootDeviceName)
		}
		if len(requested) > 0 {
			return ec2Failure("UnsupportedOperation", "CreateImage requires mappings backed by current attached EBS volumes.")
		}
		if !rootFound {
			return ec2Failure("InvalidBlockDeviceMapping", "The instance has no attached EBS root volume.")
		}
		return nil
	})
	return out, err
}

// CaptureImageSnapshots is never called inside a metadata transaction. The
// independent targets are temporary; readers use only normal snapshot blocks.
func (s *Service) CaptureImageSnapshots(ctx context.Context, ids []string) error {
	return s.captureImageSnapshots(ctx, ids, false)
}

// ResumeImageSnapshots never chooses a new capture point after interruption.
func (s *Service) ResumeImageSnapshots(ctx context.Context, ids []string) error {
	return s.captureImageSnapshots(ctx, ids, true)
}

func (s *Service) captureImageSnapshots(ctx context.Context, ids []string, recovery bool) error {
	defer s.jobs.Wake()
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	records := make([]SnapshotRecord, 0, len(ids))
	if err := s.repository.View(ctx, func(r Reader) error {
		for _, id := range ids {
			v, err := r.Snapshot(SnapshotKey{Scope: scopeFor(ctx), ID: id})
			if err != nil {
				return err
			}
			if v.Volume == nil {
				return errors.New("image snapshot has no volume source")
			}
			if v.StateMessage != "" {
				return errors.New(v.StateMessage)
			}
			if !v.Sealed && v.Volume.NativeBackupPath != "" {
				records = append(records, v)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	interrupted := false
	for _, v := range records {
		interrupted = interrupted || !v.Volume.NativeWorkAt.IsZero()
	}
	if interrupted || recovery {
		for _, v := range records {
			if !v.Volume.NativeBackupReady {
				cause := errors.New("image native capture was interrupted before the original capture point completed")
				if err := s.failNativeSnapshot(ctx, v, cause); err != nil {
					return err
				}
				return cause
			}
			if err := s.resumeNativeSnapshot(ctx, v); err != nil {
				return err
			}
		}
		return nil
	}
	return s.captureNativeSnapshots(ctx, records)
}

func (s *Service) FailImageSnapshots(ctx context.Context, ids []string, message string) error {
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	for _, id := range ids {
		var v SnapshotRecord
		if err := s.repository.View(ctx, func(r Reader) error {
			var err error
			v, err = r.Snapshot(SnapshotKey{Scope: scopeFor(ctx), ID: id})
			return err
		}); err != nil {
			return err
		}
		if volumeSnapshotBlocksPending(v) {
			if err := s.finishVolumeSnapshotBlocks(ctx, v, errors.New(message)); err != nil {
				return err
			}
		} else if v.Volume != nil && !v.Sealed {
			if err := s.failNativeSnapshot(ctx, v, errors.New(message)); err != nil {
				return err
			}
		}
	}
	s.jobs.Wake()
	return nil
}
