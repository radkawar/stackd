package ec2

import (
	"context"
	"errors"
	"strings"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
)

func instanceAttachmentWork(record InstanceRecord) bool {
	for _, mapping := range record.Data.BlockDeviceMappings {
		if mapping.Ebs != nil && (str(mapping.Ebs.Status) == "attaching" || str(mapping.Ebs.Status) == "detaching") {
			return true
		}
	}
	return false
}

// reconcileInstanceVolumes is run under instanceWorkMu, outside resource
// transactions. A stopped instance owns logical EBS attachments but has no
// guest device; a running instance completes only actual native effects.
func (s *Service) reconcileInstanceVolumes(ctx context.Context, record InstanceRecord, handle native.Instance) error {
	for _, mapping := range record.Data.BlockDeviceMappings {
		if mapping.Ebs == nil {
			continue
		}
		status := str(mapping.Ebs.Status)
		if status != "attaching" && status != "detaching" {
			continue
		}
		single := record.Data
		single.BlockDeviceMappings = api.InstanceBlockDeviceMappingList{mapping}
		complete := false
		if instanceState(record) == "stopped" {
			complete = true
		} else if handle != nil {
			if status == "attaching" {
				refs, err := s.instanceVolumes.ResolveInstanceVolumes(ctx, single)
				if err != nil && !errors.Is(err, native.ErrNotFound) {
					return err
				}
				if err == nil && len(refs) == 1 {
					attached, err := handle.AttachedDisks(ctx)
					if err != nil {
						return err
					}
					for _, disk := range attached {
						if disk.Device != "" && disk.Path == refs[0].Path && disk.Encrypted == refs[0].Encrypted && disk.Root == refs[0].Root && disk.Serial == strings.ReplaceAll(str(mapping.Ebs.VolumeId), "-", "") {
							complete = true
							break
						}
					}
				}
				if !complete {
					disks, err := s.instanceVolumes.PrepareInstanceVolumes(ctx, single)
					if err != nil {
						return err
					}
					if len(disks) != 1 {
						for _, disk := range disks {
							clear(disk.Key)
						}
						return errors.New("ec2: attachment preparation did not resolve exactly one volume")
					}
					err = handle.AttachDisk(ctx, disks[0])
					clear(disks[0].Key)
					if err != nil {
						return err
					}
					// Success requires observed native qdev realization, not only device_add.
					complete = true
				}
			} else {
				disks, err := s.instanceVolumes.ResolveInstanceVolumes(ctx, single)
				if err != nil && !errors.Is(err, native.ErrNotFound) {
					return err
				}
				if errors.Is(err, native.ErrNotFound) {
					complete = true
				} else {
					if len(disks) != 1 {
						return errors.New("ec2: attachment resolution did not resolve exactly one volume")
					}
					detachCtx, cancel := context.WithTimeout(ctx, time.Second)
					err = handle.DetachDisk(detachCtx, disks[0])
					cancel()
					if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
						// Native device_del may still await the guest. Keep ownership and
						// observe again on the next scheduler deadline, without claiming success.
						continue
					}
					if err != nil {
						return err
					}
					complete = true
				}
				if complete {
					if err := s.instanceVolumes.StopInstanceVolumes(ctx, single); err != nil {
						return err
					}
				}
			}
		}
		if !complete {
			continue
		}
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Instance(record.Key)
			if err != nil {
				return err
			}
			if current.Generation != record.Generation {
				return nil
			}
			for index, retained := range current.Data.BlockDeviceMappings {
				if retained.Ebs == nil || str(retained.Ebs.VolumeId) != str(mapping.Ebs.VolumeId) || str(retained.Ebs.Status) != status {
					continue
				}
				if status == "detaching" {
					current.Data.BlockDeviceMappings = append(current.Data.BlockDeviceMappings[:index], current.Data.BlockDeviceMappings[index+1:]...)
				} else {
					current.Data.BlockDeviceMappings[index].Ebs.Status = new(api.AttachmentStatus("attached"))
				}
				if instanceState(current) == "stopped" && !instanceAttachmentWork(current) {
					current.NextActionAt = time.Time{}
				}
				return tx.PutInstance(current)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) resolveExistingInstanceDisks(ctx context.Context, record InstanceRecord) ([]native.Disk, error) {
	disks := make([]native.Disk, 0, len(record.Data.BlockDeviceMappings))
	for _, mapping := range record.Data.BlockDeviceMappings {
		if mapping.Ebs == nil {
			continue
		}
		single := record.Data
		single.BlockDeviceMappings = api.InstanceBlockDeviceMappingList{mapping}
		resolved, err := s.instanceVolumes.ResolveInstanceVolumes(ctx, single)
		if errors.Is(err, native.ErrNotFound) && str(mapping.DeviceName) != str(record.Data.RootDeviceName) {
			continue
		}
		if err != nil {
			return nil, err
		}
		disks = append(disks, resolved...)
	}
	return disks, nil
}
