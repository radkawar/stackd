package ebs

import (
	"context"
	"errors"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/ec2"
)

func instanceVolumeFailure(message string) error {
	return &ec2.InstanceLaunchFailure{Code: "Client.InvalidKMSKey.InvalidState", Message: message}
}

// ResolveInstanceVolumes returns native.ErrNotFound when a mapped disk has no
// committed native authority. Hydration commits before VM creation, so callers
// must prepare rather than attempt to reopen a fabricated disk reference.
func (s *Service) ResolveInstanceVolumes(ctx context.Context, instance api.Instance) ([]native.Disk, error) {
	disks := make([]native.Disk, 0, len(instance.BlockDeviceMappings))
	err := s.repository.View(ctx, func(r Reader) error {
		for _, mapping := range instance.BlockDeviceMappings {
			if mapping.Ebs == nil || value(mapping.Ebs.Status) == "detached" {
				continue
			}
			v, err := r.Volume(VolumeKey{Scope: scopeFor(ctx), ID: value(mapping.Ebs.VolumeId)})
			if err != nil {
				return err
			}
			if v.Creation != nil || v.NativePath == "" {
				return native.ErrNotFound
			}
			if v.Status == api.VolumeStateDeleted || v.Status == api.VolumeStateDeleting {
				return volumeMissing(v.Key.ID)
			}
			disk := nativeVolumeDisk(v)
			disk.Root = value(mapping.DeviceName) == value(instance.RootDeviceName)
			disks = append(disks, disk)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return disks, err
}

func (s *Service) PrepareInstanceVolumes(ctx context.Context, instance api.Instance) ([]native.Disk, error) {
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	disks := make([]native.Disk, 0, len(instance.BlockDeviceMappings))
	success := false
	defer func() {
		if !success {
			for _, disk := range disks {
				clear(disk.Key)
			}
		}
	}()
	for _, mapping := range instance.BlockDeviceMappings {
		if mapping.Ebs == nil || value(mapping.Ebs.Status) == "detached" || value(mapping.Ebs.Status) == "detaching" {
			continue
		}
		var v VolumeRecord
		var key []byte
		err := s.repository.View(ctx, func(r Reader) error {
			var err error
			v, err = r.Volume(VolumeKey{Scope: scopeFor(ctx), ID: value(mapping.Ebs.VolumeId)})
			return err
		})
		if err != nil {
			return nil, err
		}
		if v.Creation != nil {
			if err := s.hydrateVolumeCreation(ctx, v); err != nil {
				return nil, err
			}
		}
		var rejected error
		err = s.repository.Update(ctx, func(tx Transaction) error {
			var err error
			v, err = tx.Volume(VolumeKey{Scope: scopeFor(ctx), ID: value(mapping.Ebs.VolumeId)})
			if err != nil {
				return err
			}
			if v.StateMessage != "" {
				return instanceVolumeFailure(v.StateMessage)
			}
			if v.Status == api.VolumeStateDeleted || v.Status == api.VolumeStateDeleting {
				return volumeMissing(v.Key.ID)
			}
			if !v.Encrypted {
				return nil
			}
			if s.instanceKeys == nil {
				return errors.New("instance EBS encryption is not configured")
			}
			if v.InfrastructureGrantID == "" {
				return instanceVolumeFailure("Instance infrastructure grant was not admitted.")
			}
			plain, failure := s.instanceKeys.DecryptInstanceVolume(tx.Context(), v, value(instance.InstanceId))
			key = plain
			if failure != nil {
				rejected = instanceVolumeFailure(failure.Message)
			}
			if failure == nil && len(key) != 64 {
				rejected = errors.New("EBS KMS data key must contain 64 bytes")
			}
			return nil
		})
		if err != nil {
			clear(key)
			return nil, err
		}
		if rejected != nil {
			clear(key)
			return nil, rejected
		}
		disk, err := s.hydrateNativeVolume(ctx, v, key)
		if err != nil {
			clear(key)
			return nil, err
		}
		disk.Root = value(mapping.DeviceName) == value(instance.RootDeviceName)
		disks = append(disks, disk)
	}
	success = true
	return disks, nil
}

func (s *Service) retireInfrastructureGrant(ctx context.Context, v *VolumeRecord) error {
	if v.InfrastructureGrantID == "" {
		return nil
	}
	if s.instanceKeys == nil {
		return errors.New("instance EBS encryption is not configured")
	}
	if rejected := s.instanceKeys.RetireInstanceVolumeGrant(ctx, *v, v.InfrastructureGrantID); rejected != nil {
		return rejected
	}
	v.InfrastructureGrantID = ""
	return nil
}

// Stop changes only infrastructure authority, never EC2's attachment relationship.
func (s *Service) StopInstanceVolumes(ctx context.Context, instance api.Instance) error {
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	return s.repository.Update(ctx, func(tx Transaction) error {
		for _, mapping := range instance.BlockDeviceMappings {
			if mapping.Ebs == nil || value(mapping.Ebs.Status) == "detached" {
				continue
			}
			v, err := tx.Volume(VolumeKey{Scope: scopeFor(ctx), ID: value(mapping.Ebs.VolumeId)})
			if err != nil {
				return err
			}
			if err := s.retireInfrastructureGrant(tx.Context(), &v); err != nil {
				return err
			}
			if err := tx.PutVolume(v); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) deleteNativeVolume(ctx context.Context, v VolumeRecord) error {
	var pending bool
	err := s.repository.View(ctx, func(r Reader) error { var err error; pending, err = s.nativeSnapshotPending(r, v); return err })
	if err != nil {
		return err
	}
	if pending {
		return errors.New("volume has a pending native snapshot backup")
	}
	disk := nativeVolumeDisk(v)
	if disk.Path == "" {
		if s.nativeDisks == nil || s.nativeVolumeDirectory == "" {
			return nil
		}
		disk.Path, err = s.volumeNativePath(v)
		if err != nil {
			return err
		}
	}
	if s.nativeDisks == nil {
		return errors.New("native EBS disk storage is not configured")
	}
	// DeleteDisk checks real native writers, including a VMM surviving controller
	// loss. No metadata-only attachment transition may bypass that exclusion.
	return s.nativeDisks.DeleteDisk(ctx, disk)
}

func (s *Service) retireVolumeGrants(ctx context.Context, v *VolumeRecord) error {
	if err := s.retireInfrastructureGrant(ctx, v); err != nil {
		return err
	}
	if v.ServiceGrantID != "" {
		if s.ec2Keys == nil {
			return errors.New("EC2 volume encryption is not configured")
		}
		if rejected := s.ec2Keys.RetireVolumeCreationGrant(ctx, *v); rejected != nil {
			return rejected
		}
		v.ServiceGrantID = ""
	}
	return nil
}

func (s *Service) TerminateInstanceVolumes(ctx context.Context, instance api.Instance) error {
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	for _, mapping := range instance.BlockDeviceMappings {
		if mapping.Ebs == nil || value(mapping.Ebs.Status) == "detached" {
			continue
		}
		k := VolumeKey{Scope: scopeFor(ctx), ID: value(mapping.Ebs.VolumeId)}
		var v VolumeRecord
		err := s.repository.View(ctx, func(r Reader) error { var err error; v, err = r.Volume(k); return err })
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		remove := mapping.Ebs.DeleteOnTermination != nil && bool(*mapping.Ebs.DeleteOnTermination)
		if remove {
			if err := s.deleteNativeVolume(ctx, v); err != nil {
				return err
			}
		}
		err = s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Volume(k)
			if err != nil {
				return err
			}
			if remove {
				if err := s.retireVolumeGrants(tx.Context(), &current); err != nil {
					return err
				}
				if err := deleteUnpinnedVolumeBlocks(tx, k); err != nil {
					return err
				}
				if current.Creation != nil {
					source := current.Creation.Source
					current.Creation = nil
					if err := tx.PutVolume(current); err != nil {
						return err
					}
					if err := pruneLayers(tx, source.Scope); err != nil {
						return err
					}
				}
				current.NativePath = ""
				current.WrappedKey = nil
				current.Modification = nil
				current.TransitionAt = time.Time{}
				deleted := current.Status == api.VolumeStateDeleted
				current.Status = api.VolumeStateDeleted
				if err := tx.PutVolume(current); err != nil {
					return err
				}
				if !deleted {
					return s.publishVolumeEvent(tx.Context(), current, "deleteVolume", "deleted", s.clock.Now())
				}
				return nil
			}
			if err := s.retireInfrastructureGrant(tx.Context(), &current); err != nil {
				return err
			}
			if current.Creation == nil && current.Status != api.VolumeStateDeleted && current.Status != api.VolumeStateDeleting {
				current.Status = api.VolumeStateAvailable
			}
			return tx.PutVolume(current)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
