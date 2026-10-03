package ec2

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	native "stackd/compute/ec2"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// InstanceImageSnapshots owns image-derived snapshots in the existing EBS
// catalog. Admission joins the image transaction; all native work is outside it.
type InstanceImageSnapshots interface {
	AdmitImageSnapshots(context.Context, api.Instance, string, api.BlockDeviceMappingRequestList, api.TagList) (api.BlockDeviceMappingList, error)
	CaptureImageSnapshots(context.Context, []string) error
	ResumeImageSnapshots(context.Context, []string) error
	FailImageSnapshots(context.Context, []string, string) error
}

// ImageCreation is the image's own recovery state, not another job ledger.
// Generation claims the source while public state remains running or stopped.
type ImageCreation struct {
	InstanceID                     string
	InstanceGeneration             uint64
	NoReboot                       bool
	Phase                          string
	NextActionAt, ShutdownDeadline time.Time
	RequestID, ParentEventID       string
}

func registerInstanceImages(s *Service) {
	if s.instanceImages != nil {
		registerExternalOwnedCommand(s, "CreateImage", s.createImage)
	}
}

func (s *Service) createImage(ctx context.Context, in *api.CreateImageRequest) (*api.CreateImageResult, error) {
	s.instanceWorkMu.Lock()
	defer s.instanceWorkMu.Unlock()
	var image ImageRecord
	out := &api.CreateImageResult{}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		records, err := s.instanceCommandTargets(ctx, tx, "CreateImage", api.InstanceIdStringList{api.InstanceId(str(in.InstanceId))}, nil)
		if err != nil {
			return err
		}
		record := records[0]
		state := instanceState(record)
		if state != "running" && state != "stopped" {
			return failure("IncorrectInstanceState", "The instance must be running or stopped to create an image.")
		}
		if state == "running" && (record.Intent != InstanceIntentObserve || record.NextActionAt.IsZero()) {
			return failure("IncorrectInstanceState", "The instance already has an active native operation.")
		}
		if err := admitImageName(ctx, tx, str(in.Name)); err != nil {
			return err
		}
		if utf8.RuneCountInString(str(in.Description)) > 255 {
			return failure("InvalidParameterValue", "Image description exceeds 255 characters.")
		}
		if in.SnapshotLocation != nil {
			return unsupported("SnapshotLocation requires a Local Zone or Outpost source instance.")
		}
		if in.BootModeOverride != nil && (str(in.BootModeOverride) != "uefi" || str(record.Data.CurrentInstanceBootMode) != "uefi") {
			return failure("InvalidParameterValue", "BootModeOverride requires a source currently booted in UEFI mode.")
		}
		var imageSpecifications, snapshotSpecifications api.TagSpecificationList
		for _, spec := range in.TagSpecifications {
			switch str(spec.ResourceType) {
			case "image":
				imageSpecifications = append(imageSpecifications, spec)
			case "snapshot":
				snapshotSpecifications = append(snapshotSpecifications, spec)
			default:
				return failure("InvalidParameterValue", "CreateImage tags support only image and snapshot resources.")
			}
		}
		imageTags, err := CreationTags(imageSpecifications, "image")
		if err != nil {
			return err
		}
		snapshotTags, err := CreationTags(snapshotSpecifications, "snapshot")
		if err != nil {
			return err
		}
		if err := s.authorizeCreateWith(ctx, "CreateImage", "image", "*", imageTags, map[string][]string{"ec2:ImageID": {"*"}, "ec2:Owner": {scopeFor(ctx).AccountID}}); err != nil {
			return err
		}
		id, err := tx.NextID(scopeFor(ctx), "ami")
		if err != nil {
			return err
		}
		mappings, err := s.instanceImages.AdmitImageSnapshots(ctx, record.Data, id, in.BlockDeviceMappings, snapshotTags)
		if err != nil {
			return err
		}
		if err := dryRun(in.DryRun); err != nil {
			return err
		}
		if imageTags == nil {
			imageTags = api.TagList{}
		}
		phase := "capture"
		if state == "running" && !boolValue(in.NoReboot) {
			phase = "shutdown"
		}
		record.Generation++
		if state == "running" {
			record.NextActionAt = time.Time{}
		}
		if err := tx.PutInstance(record); err != nil {
			return err
		}
		image = ImageRecord{Key: key(ctx, id), LaunchPermissions: api.LaunchPermissionList{}, SnapshotOwners: map[string]string{}, Create: &ImageCreation{
			InstanceID: record.Key.ID, InstanceGeneration: record.Generation, NoReboot: boolValue(in.NoReboot), Phase: phase,
			NextActionAt: s.clock.Now(), ShutdownDeadline: s.clock.Now().Add(2 * time.Minute), RequestID: awsctx.FromContext(ctx).RequestID, ParentEventID: apievents.EventID(ctx),
		}, Data: api.Image{
			ImageId: new(api.String(id)), Name: new(api.String(str(in.Name))), Description: new(api.String(str(in.Description))), OwnerId: new(api.String(scopeFor(ctx).AccountID)),
			ImageLocation: new(api.String(scopeFor(ctx).AccountID + "/" + str(in.Name))), Architecture: copyPointer(record.Data.Architecture), VirtualizationType: copyPointer(record.Data.VirtualizationType),
			ImageType: new(api.ImageTypeValues("machine")), State: new(api.ImageState("pending")), Public: new(api.Boolean(false)), RootDeviceType: copyPointer(record.Data.RootDeviceType), RootDeviceName: copyPointer(record.Data.RootDeviceName), BlockDeviceMappings: mappings,
			BootMode: copyPointer(record.Data.BootMode), EnaSupport: copyPointer(record.Data.EnaSupport), Hypervisor: copyPointer(record.Data.Hypervisor), Platform: copyPointer(record.Data.Platform), PlatformDetails: copyPointer(record.Data.PlatformDetails), UsageOperation: copyPointer(record.Data.UsageOperation),
			FreeTierEligible:         new(api.Boolean(true)),
			DeregistrationProtection: new(api.String("disabled")), CreationDate: new(api.String(s.clock.Now().UTC().Format("2006-01-02T15:04:05.000Z"))), Tags: imageTags,
			SourceInstanceId: new(api.String(record.Key.ID)), SourceImageId: copyPointer(record.Data.ImageId), SourceImageRegion: new(api.String(record.Key.Scope.Region)),
		}}
		if in.BootModeOverride != nil {
			image.Data.BootMode = new(api.BootModeValues("uefi"))
		}
		if source, err := tx.RegionalImage(record.Key.Scope, str(record.Data.ImageId)); err == nil {
			image.Data.ImdsSupport = copyPointer(source.Data.ImdsSupport)
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		for _, mapping := range mappings {
			if mapping.Ebs != nil {
				image.SnapshotOwners[str(mapping.Ebs.SnapshotId)] = scopeFor(ctx).AccountID
			}
		}
		if err := tx.PutImage(image); err != nil {
			return err
		}
		out.ImageId = image.Data.ImageId
		return RecordExternalSuccess(ctx, out)
	})
	if err != nil {
		return nil, err
	}
	// NoReboot and stopped sources fix their disk capture at this admitted API
	// edge. Rebooted sources request real guest shutdown immediately; only its
	// observed Shutdown state permits buffered data to be considered flushed.
	_ = s.advanceImage(ctx, image)
	return out, nil
}

func imageSnapshotIDs(image ImageRecord) []string {
	ids := make([]string, 0, len(image.Data.BlockDeviceMappings))
	for _, mapping := range image.Data.BlockDeviceMappings {
		if mapping.Ebs != nil && str(mapping.Ebs.SnapshotId) != "" {
			ids = append(ids, str(mapping.Ebs.SnapshotId))
		}
	}
	return ids
}

func (s *Service) NextImageDeadline(ctx context.Context) (time.Time, bool, error) {
	var next time.Time
	var found bool
	err := s.repository.View(ctx, func(tx Reader) error { var err error; next, found, err = tx.NextImageDeadline(); return err })
	return next, found, err
}

func (s *Service) AdvanceImages(ctx context.Context) (int, error) {
	if s.instanceImages == nil {
		return 0, nil
	}
	s.instanceWorkMu.Lock()
	defer s.instanceWorkMu.Unlock()
	var images []ImageRecord
	if err := s.repository.View(ctx, func(tx Reader) error { var err error; images, err = tx.PendingImages(s.clock.Now()); return err }); err != nil {
		return 0, err
	}
	for i, image := range images {
		child := instanceServiceContext(ctx, ResourceKey{Scope: image.Key.Scope, ID: image.Create.InstanceID})
		if err := s.advanceImageRecovery(child, image); err != nil {
			return i, err
		}
	}
	return len(images), nil
}

func (s *Service) advanceImageRecovery(ctx context.Context, image ImageRecord) error {
	if image.Create != nil && image.Create.Phase == "capture" {
		if err := s.instanceImages.ResumeImageSnapshots(ctx, imageSnapshotIDs(image)); err != nil {
			return s.failInstanceImage(ctx, image, err, false)
		}
		return s.setImagePhase(ctx, image, "wait")
	}
	return s.advanceImage(ctx, image)
}

func (s *Service) advanceImage(ctx context.Context, image ImageRecord) error {
	var record InstanceRecord
	if err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		image, err = tx.Image(image.Key)
		if err != nil {
			return err
		}
		if image.Create == nil {
			return nil
		}
		record, err = tx.Instance(ResourceKey{Scope: image.Key.Scope, ID: image.Create.InstanceID})
		return err
	}); err != nil {
		return err
	}
	if image.Create == nil {
		return nil
	}
	if image.Create.Phase == "wait" {
		return s.completeInstanceImage(ctx, image)
	}
	// Metadata and attachment admissions may change Generation without taking
	// over the image-owned reboot. A new lifecycle intent, not an unrelated
	// metadata version, cancels that work.
	if record.Generation != image.Create.InstanceGeneration && (instanceState(record) != "running" || record.Intent != InstanceIntentObserve) {
		return s.failInstanceImage(ctx, image, errors.New("source instance operation changed during image creation"), false)
	}
	switch image.Create.Phase {
	case "shutdown", "shutdown-wait":
		handle, err := s.creditInstanceHandle(ctx, record)
		if err != nil {
			return s.failInstanceImage(ctx, image, err, false)
		}
		status, err := handle.Inspect(ctx)
		if err != nil {
			return err
		}
		if status.State == native.Shutdown {
			cpu, err := s.beforeInstanceCreditStop(ctx, record.Key, handle)
			if err != nil {
				return err
			}
			admitted, err := s.checkpointImageShutdown(ctx, image, record, handle, cpu)
			if err != nil {
				return err
			}
			if !admitted {
				return nil
			}
			image.Create.Phase = "capture-reboot"
			return s.captureInstanceImage(ctx, image, true)
		}
		if status.State != native.Running {
			return s.failInstanceImage(ctx, image, errors.New("guest exited without an observed graceful shutdown"), false)
		}
		if _, err := s.pollInstanceCredits(ctx, record.Key, handle); err != nil {
			return err
		}
		if !s.clock.Now().Before(image.Create.ShutdownDeadline) {
			return s.failInstanceImage(ctx, image, errors.New("guest did not acknowledge graceful shutdown before the image reboot deadline; no consistent snapshot was taken"), false)
		}
		if image.Create.Phase == "shutdown" {
			if err := handle.Powerdown(ctx); err != nil {
				return s.failInstanceImage(ctx, image, err, false)
			}
		}
		return s.setImagePhase(ctx, image, "shutdown-wait")
	case "capture":
		return s.captureInstanceImage(ctx, image, false)
	case "capture-reboot":
		return s.captureInstanceImage(ctx, image, true)
	case "boot":
		if err := s.rebootImageSource(ctx, image, record); err != nil {
			return s.failInstanceImage(ctx, image, err, true)
		}
		return nil
	default:
		return s.failInstanceImage(ctx, image, errors.New("unknown image creation phase"), false)
	}
}

func (s *Service) captureInstanceImage(ctx context.Context, image ImageRecord, reboot bool) error {
	if err := s.instanceImages.CaptureImageSnapshots(ctx, imageSnapshotIDs(image)); err != nil {
		return s.failInstanceImage(ctx, image, err, reboot)
	}
	phase := "wait"
	if reboot {
		phase = "boot"
	}
	return s.setImagePhase(ctx, image, phase)
}

func (s *Service) setImagePhase(ctx context.Context, image ImageRecord, phase string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Image(image.Key)
		if err != nil {
			return err
		}
		if current.Create == nil {
			return nil
		}
		current.Create.Phase = phase
		current.Create.NextActionAt = s.clock.Now().Add(time.Second)
		if phase == "wait" {
			if err := s.releaseImageSource(tx, current); err != nil {
				return err
			}
		}
		return tx.PutImage(current)
	})
}

func (s *Service) releaseImageSource(tx Transaction, image ImageRecord) error {
	record, err := tx.Instance(ResourceKey{Scope: image.Key.Scope, ID: image.Create.InstanceID})
	if err != nil {
		return err
	}
	if instanceState(record) != "running" || record.Intent != InstanceIntentObserve {
		return nil
	}
	record.NextActionAt = s.clock.Now()
	return tx.PutInstance(record)
}

func (s *Service) failInstanceImage(ctx context.Context, image ImageRecord, cause error, reboot bool) error {
	if err := s.instanceImages.FailImageSnapshots(ctx, imageSnapshotIDs(image), cause.Error()); err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Image(image.Key)
		if err != nil {
			return err
		}
		if current.Create == nil {
			return nil
		}
		current.Data.State = new(api.ImageState("failed"))
		current.Data.StateReason = &api.StateReason{Code: new(api.String("Server.ImageCreationFailed")), Message: new(api.String(cause.Error()))}
		if reboot {
			current.Create.Phase = "boot"
			current.Create.NextActionAt = s.clock.Now().Add(time.Second)
		} else {
			if err := s.releaseImageSource(tx, current); err != nil {
				return err
			}
			current.Create = nil
		}
		return tx.PutImage(current)
	})
}

// rebootImageSource replaces only a gracefully shut-down VMM. It retains all
// public instance/volume/ENI relationships and does not create StopInstances
// state transitions or force-kill a running, unresponsive guest.
func (s *Service) rebootImageSource(ctx context.Context, image ImageRecord, record InstanceRecord) error {
	spec, err := s.instanceSpecification(ctx, record)
	if err != nil {
		return err
	}
	handle := s.instanceHandles[record.Key]
	if handle == nil {
		spec.Disks, err = s.instanceVolumes.ResolveInstanceVolumes(ctx, record.Data)
		if err != nil {
			return err
		}
		handle, err = s.instanceRuntime.Reopen(ctx, spec)
		if err != nil && !errors.Is(err, native.ErrNotFound) {
			return err
		}
		if errors.Is(err, native.ErrNotFound) {
			handle = nil
		}
	}
	if handle != nil {
		status, err := handle.Inspect(ctx)
		if err != nil {
			return err
		}
		if status.State == native.Shutdown {
			// Credits and performance were checkpointed at the observed Shutdown
			// edge, before capture. Resampling would include backup downtime.
			if err := handle.Stop(ctx); err != nil {
				return err
			}
			if err := handle.Close(); err != nil {
				return err
			}
			delete(s.instanceHandles, record.Key)
			handle = nil
		} else if status.State == native.Exited {
			if err := handle.Close(); err != nil {
				return err
			}
			delete(s.instanceHandles, record.Key)
			handle = nil
		} else if status.State == native.Running {
			return s.finishImageReboot(ctx, image)
		}
	}
	if handle == nil {
		spec.Disks, err = s.instanceVolumes.PrepareInstanceVolumes(ctx, record.Data)
		if err != nil {
			return err
		}
		handle, err = s.instanceRuntime.Prepare(ctx, spec)
		for i := range spec.Disks {
			clear(spec.Disks[i].Key)
			spec.Disks[i].Key = nil
		}
		if err != nil {
			return err
		}
		if s.instanceHandles == nil {
			s.instanceHandles = map[ResourceKey]native.Instance{}
		}
		s.instanceHandles[record.Key] = handle
	}
	if err := s.beforeInstanceCreditReboot(ctx, record.Key, handle); err != nil {
		return err
	}
	if err := handle.Start(ctx); err != nil {
		return err
	}
	status, err := handle.Inspect(ctx)
	if err != nil {
		return err
	}
	if status.State != native.Running {
		return errors.New("image source VMM did not resume execution")
	}
	return s.finishImageReboot(ctx, image)
}

func (s *Service) finishImageReboot(ctx context.Context, image ImageRecord) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Image(image.Key)
		if err != nil {
			return err
		}
		if current.Create == nil {
			return nil
		}
		if err := s.releaseImageSource(tx, current); err != nil {
			return err
		}
		if str(current.Data.State) == "failed" {
			current.Create = nil
		} else {
			current.Create.Phase = "wait"
			current.Create.NextActionAt = s.clock.Now().Add(time.Second)
		}
		return tx.PutImage(current)
	})
}

func (s *Service) completeInstanceImage(ctx context.Context, image ImageRecord) error {
	snapshots, err := s.imageSnapshots.ResolveImageSnapshots(ctx, imageSnapshotIDs(image))
	if err != nil {
		return s.failInstanceImage(ctx, image, err, false)
	}
	complete := true
	for _, snapshot := range snapshots {
		if str(snapshot.State) == "error" {
			return s.failInstanceImage(ctx, image, errors.New("an image snapshot failed"), false)
		}
		complete = complete && str(snapshot.State) == "completed"
	}
	if !complete {
		return s.setImagePhase(ctx, image, "wait")
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Image(image.Key)
		if err != nil {
			return err
		}
		if current.Create == nil {
			return nil
		}
		if str(current.Data.State) == "pending" {
			current.Data.State = new(api.ImageState("available"))
		}
		current.Create = nil
		return tx.PutImage(current)
	})
}
