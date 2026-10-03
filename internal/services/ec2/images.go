package ec2

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
)

func registerImages(s *Service) {
	if s.imageSnapshots != nil {
		register(s, "RegisterImage", s.registerImage)
	}
	register(s, "DescribeImages", s.describeImages)
	register(s, "DescribeImageAttribute", s.describeImageAttribute)
	register(s, "ModifyImageAttribute", s.modifyImageAttribute)
	register(s, "ResetImageAttribute", s.resetImageAttribute)
	register(s, "DeregisterImage", s.deregisterImage)
}

func validateImageID(id string) error {
	if id == "" {
		return failure("MissingParameter", "The request must contain the parameter ImageId")
	}
	// TODO: Comeback validate opaque AWS AMI ID encoding beyond public hex
	// syntax. Unknown-ID validity is explicitly deferred; do not blacklist
	// individual captured IDs or change issued/deleted image lookup semantics.
	valid := strings.HasPrefix(id, "ami-") && (len(id) == 12 || len(id) == 21)
	nonzero := false
	if valid {
		for _, c := range id[4:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				valid = false
				break
			}
			nonzero = nonzero || c != '0'
		}
	}
	if !valid || !nonzero {
		return failure("InvalidAMIID.Malformed", "Invalid id: \""+id+"\"")
	}
	return nil
}

func imageNotFound(id string) error {
	return failure("InvalidAMIID.NotFound", "The image id '["+id+"]' does not exist")
}

func duplicateImageName(name string) error {
	return failure("InvalidAMIName.Duplicate", "AMI name "+name+" is already in use by another AMI.")
}

// admitImageName is shared by RegisterImage and CreateImage before either
// publishes catalog state or creates snapshot effects.
func admitImageName(ctx context.Context, tx Reader, name string) error {
	if len(name) < 3 || len(name) > 128 {
		return failure("InvalidAMIName.Malformed", "AMI names must be between 3 and 128 characters long.")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("()[] ./-'@_", c)) {
			return failure("InvalidAMIName.Malformed", "AMI name contains invalid characters.")
		}
	}
	images, err := tx.Images(scopeFor(ctx))
	if err != nil {
		return err
	}
	for _, image := range images {
		if str(image.Data.State) != "deregistered" && str(image.Data.Name) == name {
			return duplicateImageName(name)
		}
	}
	return nil
}

func imageConditions(image ImageRecord) map[string][]string {
	return map[string][]string{
		"ec2:ImageID": {image.Key.ID}, "ec2:ImageType": {str(image.Data.ImageType)},
		"ec2:Owner": {image.Key.Scope.AccountID}, "ec2:Public": {strconv.FormatBool(boolValue(image.Data.Public))},
		"ec2:RootDeviceType": {str(image.Data.RootDeviceType)},
	}
}

func (s *Service) authorizeImage(ctx context.Context, action string, image ImageRecord, extra map[string][]string) error {
	conditions := imageConditions(image)
	for k, values := range extra {
		conditions[k] = values
	}
	conditions["ec2:Region"] = []string{image.Key.Scope.Region}
	addLaunchTemplateConditions(ctx, action, "image", image.Key.ID, conditions)
	for _, tag := range image.Data.Tags {
		conditions["aws:ResourceTag/"+str(tag.Key)] = []string{str(tag.Value)}
		conditions["ec2:ResourceTag/"+str(tag.Key)] = []string{str(tag.Value)}
	}
	now := s.clock.Now()
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "ec2:" + action,
		ResourceARN: resourceARN(image.Key.Scope, "image", image.Key.ID), ResourceAccountID: image.Key.Scope.AccountID,
		Context: conditions, EvaluationTime: &now}); denied != nil {
		return denied
	}
	return nil
}

func imageVisible(image ImageRecord, account string) bool {
	if image.Key.Scope.AccountID == account {
		return true
	}
	for _, permission := range image.LaunchPermissions {
		if str(permission.Group) == "all" || str(permission.UserId) == account {
			return true
		}
	}
	return false
}

func resolveVisibleImage(ctx context.Context, tx Reader, id string) (ImageRecord, error) {
	if err := validateImageID(id); err != nil {
		return ImageRecord{}, err
	}
	scope := scopeFor(ctx)
	image, err := tx.RegionalImage(scope, id)
	if errors.Is(err, ErrNotFound) || err == nil && !imageVisible(image, scope.AccountID) {
		return ImageRecord{}, imageNotFound(id)
	}
	return image, err
}

// resolveLaunchImage selects the authoritative visible, available image for
// RunInstances without adding caller DescribeImages/DescribeSnapshots authority.
// The caller must authorize RunInstances on this image and its other resources.
// The returned record is detached and contains the actual EBS snapshot mappings.
func resolveLaunchImage(ctx context.Context, tx Reader, id string) (ImageRecord, error) {
	image, err := resolveVisibleImage(ctx, tx, id)
	if err != nil {
		return ImageRecord{}, err
	}
	if str(image.Data.State) != "available" {
		return ImageRecord{}, failure("InvalidAMIID.Unavailable", "The image '"+id+"' is no longer available")
	}
	return image, nil
}

func ownedImage(ctx context.Context, tx Reader, id string) (ImageRecord, error) {
	image, err := resolveVisibleImage(ctx, tx, id)
	if err != nil {
		return ImageRecord{}, err
	}
	if image.Key.Scope.AccountID != scopeFor(ctx).AccountID {
		return ImageRecord{}, failure("AuthFailure", "Not authorized for image "+id)
	}
	if str(image.Data.State) == "deregistered" {
		return ImageRecord{}, failure("InvalidAMIID.Unavailable", "The image '"+id+"' is no longer available")
	}
	return image, nil
}

func (s *Service) registerImage(ctx context.Context, tx Transaction, in *api.RegisterImageRequest) (*api.RegisterImageResult, error) {
	image, err := s.putRegisteredImage(ctx, tx, in, "RegisterImage")
	if err != nil {
		return nil, err
	}
	return &api.RegisterImageResult{ImageId: image.Data.ImageId}, nil
}

// putRegisteredImage validates EBS-backed HVM registration and atomically
// publishes available catalog state. CreateImage may reuse it after producing
// completed snapshots, passing action CreateImage (its instance/snapshot IAM
// admission remains that command's responsibility, not RegisterImage authority).
func (s *Service) putRegisteredImage(ctx context.Context, tx Transaction, in *api.RegisterImageRequest, action string) (ImageRecord, error) {
	var zero ImageRecord
	if err := admitImageName(ctx, tx, str(in.Name)); err != nil {
		return zero, err
	}
	if utf8.RuneCountInString(str(in.Description)) > 255 {
		return zero, failure("InvalidParameterValue", "Image description exceeds 255 characters.")
	}
	// TODO: Comeback support instance-store/PV/Mac registration, licensed
	// billing products, SR-IOV, NitroTPM and imported Secure Boot variables
	// with real consumers.
	if in.ImageLocation != nil || in.KernelId != nil || in.RamdiskId != nil || in.SriovNetSupport != nil || in.TpmSupport != nil || in.UefiData != nil || len(in.BillingProducts) != 0 {
		return zero, unsupported("Instance-store, kernel/ramdisk, SR-IOV, billing products, TPM and UEFI variable registration are not implemented.")
	}
	virtualization := str(in.VirtualizationType)
	if virtualization == "" {
		virtualization = "paravirtual"
	}
	if virtualization != "hvm" {
		if virtualization != "paravirtual" {
			return zero, failure("InvalidParameterValue", "Invalid virtualization type.")
		}
		return zero, unsupported("Paravirtual AMIs are not implemented; specify hvm for firmware-booted images.")
	}
	architecture := str(in.Architecture)
	if architecture == "" {
		architecture = "i386"
	}
	switch architecture {
	case "i386", "x86_64", "arm64":
	case "x86_64_mac", "arm64_mac":
		return zero, unsupported("Mac AMIs are not implemented.")
	default:
		return zero, failure("InvalidParameterValue", "Invalid image architecture.")
	}
	if in.BootMode != nil && str(in.BootMode) != "legacy-bios" && str(in.BootMode) != "uefi" && str(in.BootMode) != "uefi-preferred" {
		return zero, failure("InvalidParameterValue", "Invalid image boot mode.")
	}
	if in.ImdsSupport != nil && str(in.ImdsSupport) != "v2.0" {
		return zero, failure("InvalidParameterValue", "ImdsSupport must be v2.0.")
	}
	tags, err := CreationTags(in.TagSpecifications, "image")
	if err != nil {
		return zero, err
	}
	if err := s.authorizeCreateWith(ctx, action, "image", "*", tags, map[string][]string{"ec2:ImageID": {"*"}, "ec2:Owner": {scopeFor(ctx).AccountID}}); err != nil {
		return zero, err
	}
	mappings, owners, err := s.imageMappings(ctx, in.BlockDeviceMappings, str(in.RootDeviceName), action)
	if err != nil {
		return zero, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return zero, err
	}
	id, err := tx.NextID(scopeFor(ctx), "ami")
	if err != nil {
		return zero, err
	}
	if tags == nil {
		tags = api.TagList{}
	}
	image := ImageRecord{Key: key(ctx, id), LaunchPermissions: api.LaunchPermissionList{}, SnapshotOwners: owners, Data: api.Image{
		ImageId: new(api.String(id)), Name: new(api.String(str(in.Name))), OwnerId: new(api.String(scopeFor(ctx).AccountID)),
		ImageLocation: new(api.String(scopeFor(ctx).AccountID + "/" + str(in.Name))),
		Architecture:  new(api.ArchitectureValues(architecture)), VirtualizationType: new(api.VirtualizationType(virtualization)),
		ImageType: new(api.ImageTypeValues("machine")), State: new(api.ImageState("available")), Public: new(api.Boolean(false)),
		RootDeviceType: new(api.DeviceType("ebs")), RootDeviceName: copyPointer(in.RootDeviceName), BlockDeviceMappings: mappings,
		BootMode: copyPointer(in.BootMode), ImdsSupport: copyPointer(in.ImdsSupport), EnaSupport: copyPointer(in.EnaSupport),
		Hypervisor: new(api.HypervisorType("xen")), PlatformDetails: new(api.String("Linux/UNIX")), UsageOperation: new(api.String("RunInstances")),
		FreeTierEligible:         new(api.Boolean(true)),
		DeregistrationProtection: new(api.String("disabled")),
		CreationDate:             new(api.String(s.clock.Now().UTC().Format("2006-01-02T15:04:05.000Z"))), Tags: tags,
	}}
	if in.Description != nil {
		image.Data.Description = new(api.String(*in.Description))
	}
	return image, tx.PutImage(image)
}

func (s *Service) imageMappings(ctx context.Context, input api.BlockDeviceMappingRequestList, root, action string) (api.BlockDeviceMappingList, map[string]string, error) {
	if root == "" {
		return nil, nil, failure("InvalidBlockDeviceMapping", "RootDeviceName must identify an EBS snapshot mapping.")
	}
	ids := []string{}
	seenSnapshots := map[string]bool{}
	devices := map[string]bool{}
	rootFound := false
	for _, mapping := range input {
		device := str(mapping.DeviceName)
		if device == "" || devices[device] {
			return nil, nil, failure("InvalidBlockDeviceMapping", "Block device names must be nonempty and unique.")
		}
		devices[device] = true
		if mapping.VirtualName != nil || mapping.NoDevice != nil || mapping.Ebs == nil {
			// TODO: Comeback implement instance-store and suppressed AMI mappings.
			return nil, nil, unsupported("AMI registration supports EBS block devices only.")
		}
		ebs := mapping.Ebs
		// TODO: Comeback support AMI block-device placement/Outposts, KMS
		// overrides, initialization rates and EBS card selection.
		if ebs.AvailabilityZone != nil || ebs.AvailabilityZoneId != nil || ebs.OutpostArn != nil || ebs.KmsKeyId != nil || ebs.VolumeInitializationRate != nil || ebs.EbsCardIndex != nil {
			return nil, nil, unsupported("Placement, KMS overrides, initialization rates and EBS card selection are not supported for AMI registration.")
		}
		if ebs.Encrypted != nil {
			return nil, nil, failure("InvalidParameter", "Encrypted must not be specified when registering an image.")
		}
		sid := str(ebs.SnapshotId)
		if device == root {
			rootFound = sid != ""
		}
		if sid != "" && !seenSnapshots[sid] {
			ids = append(ids, sid)
			seenSnapshots[sid] = true
		}
	}
	if !rootFound {
		return nil, nil, failure("InvalidBlockDeviceMapping", "No root snapshot specified in device mapping.")
	}
	if s.imageSnapshots == nil {
		return nil, nil, unsupported("Image snapshot resolution is not configured.")
	}
	snapshots, err := s.imageSnapshots.ResolveImageSnapshots(ctx, ids)
	if err != nil {
		return nil, nil, imageSnapshotError(err)
	}
	byID := make(map[string]api.Snapshot, len(snapshots))
	owners := make(map[string]string, len(snapshots))
	for _, snapshot := range snapshots {
		id := str(snapshot.SnapshotId)
		byID[id] = snapshot
		owner := str(snapshot.OwnerId)
		owners[id] = owner
		if action == "RegisterImage" {
			if err := s.authorizeImageSnapshot(ctx, snapshot); err != nil {
				return nil, nil, err
			}
			// Sharing visibility does not confer RegisterImage ownership.
			if owner != scopeFor(ctx).AccountID {
				return nil, nil, failure("InvalidParameterValue", "Invalid value '"+id+"' for snapshotId. Snapshot does not belong to "+scopeFor(ctx).AccountID)
			}
		}
	}
	out := make(api.BlockDeviceMappingList, len(input))
	for i, mapping := range input {
		out[i] = api.CloneBlockDeviceMapping(mapping)
		ebs := out[i].Ebs
		if ebs.DeleteOnTermination == nil {
			ebs.DeleteOnTermination = new(api.Boolean(true))
		}
		if ebs.VolumeType == nil {
			ebs.VolumeType = new(api.VolumeType("gp2"))
		}
		if sid := str(ebs.SnapshotId); sid != "" {
			snapshot, ok := byID[sid]
			if !ok {
				return nil, nil, failure("InvalidSnapshotID.NotFound", "The snapshot ID '"+sid+"' does not exist")
			}
			if str(snapshot.State) != "completed" || str(snapshot.StorageTier) == "archive" {
				return nil, nil, failure("IncorrectState", "Snapshot "+sid+" is not completed in the standard storage tier.")
			}
			if snapshot.OutpostArn != nil {
				return nil, nil, unsupported("Outpost images are not implemented.")
			}
			if ebs.VolumeSize == nil {
				ebs.VolumeSize = copyPointer(snapshot.VolumeSize)
			}
			if ebs.VolumeSize != nil && snapshot.VolumeSize != nil && *ebs.VolumeSize < *snapshot.VolumeSize {
				return nil, nil, failure("InvalidBlockDeviceMapping", "Volume size cannot be smaller than the snapshot.")
			}
			ebs.Encrypted = new(api.Boolean(boolValue(snapshot.Encrypted)))
		} else {
			ebs.Encrypted = new(api.Boolean(false))
		}
		if err := validateImageVolume(ebs, str(mapping.DeviceName) == root); err != nil {
			return nil, nil, err
		}
	}
	return out, owners, nil
}

func validateImageVolume(ebs *api.EbsBlockDevice, root bool) error {
	if ebs.VolumeSize == nil || *ebs.VolumeSize < 1 || *ebs.VolumeSize > 65536 {
		return failure("InvalidBlockDeviceMapping", "VolumeSize must be between 1 and 65536 GiB.")
	}
	kind := str(ebs.VolumeType)
	switch kind {
	case "gp2", "gp3", "io1", "io2":
	case "standard":
		if *ebs.VolumeSize > 1024 {
			return failure("InvalidBlockDeviceMapping", "Standard volumes cannot exceed 1024 GiB.")
		}
	case "st1", "sc1":
		if root || *ebs.VolumeSize < 125 {
			return failure("InvalidBlockDeviceMapping", "HDD volumes must be at least 125 GiB and cannot be root devices.")
		}
	default:
		return failure("InvalidBlockDeviceMapping", "Invalid EBS volume type.")
	}
	if ebs.Iops != nil && (kind != "gp3" && kind != "io1" && kind != "io2" || *ebs.Iops <= 0) {
		return failure("InvalidBlockDeviceMapping", "IOPS is invalid for this volume type.")
	}
	if (kind == "io1" || kind == "io2") && ebs.Iops == nil {
		return failure("InvalidBlockDeviceMapping", "IOPS is required for provisioned-IOPS volumes.")
	}
	if ebs.Throughput != nil && (kind != "gp3" || *ebs.Throughput < 125 || *ebs.Throughput > 2000) {
		return failure("InvalidBlockDeviceMapping", "Throughput is invalid for this volume type.")
	}
	return nil
}

func (s *Service) authorizeImageSnapshot(ctx context.Context, snapshot api.Snapshot) error {
	scope := scopeFor(ctx)
	scope.AccountID = str(snapshot.OwnerId)
	conditions := map[string][]string{"ec2:Region": {scope.Region}, "ec2:Owner": {scope.AccountID}, "ec2:SnapshotID": {str(snapshot.SnapshotId)}}
	conditions["ec2:Encrypted"] = []string{strconv.FormatBool(boolValue(snapshot.Encrypted))}
	if snapshot.VolumeSize != nil {
		conditions["ec2:VolumeSize"] = []string{strconv.Itoa(int(*snapshot.VolumeSize))}
	}
	if snapshot.StartTime != nil {
		conditions["ec2:SnapshotTime"] = []string{snapshot.StartTime.UTC().Format(time.RFC3339)}
	}
	parentVolume := str(snapshot.VolumeId)
	if parentVolume == "" {
		parentVolume = "vol-ffffffff"
	}
	conditions["ec2:ParentVolume"] = []string{resourceARN(scope, "volume", parentVolume)}
	for _, tag := range snapshot.Tags {
		conditions["aws:ResourceTag/"+str(tag.Key)] = []string{str(tag.Value)}
		conditions["ec2:ResourceTag/"+str(tag.Key)] = []string{str(tag.Value)}
	}
	now := s.clock.Now()
	// Resolution has already applied snapshot visibility. As in EBS snapshot
	// authorization, retain the real owner and supply only the resource-side
	// grant; caller IAM/session/boundary/Organizations denials still apply.
	// RegisterImage enforces snapshot ownership after this IAM decision.
	foreign := scope.AccountID != "" && scope.AccountID != scopeFor(ctx).AccountID
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "ec2:RegisterImage", ResourceARN: resourceARN(scope, "snapshot", str(snapshot.SnapshotId)), ResourceAccountID: scope.AccountID, ResourceAccountGrant: foreign, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}

func (s *Service) deregisterImage(ctx context.Context, tx Transaction, in *api.DeregisterImageRequest) (*api.DeregisterImageResult, error) {
	image, err := ownedImage(ctx, tx, str(in.ImageId))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeImage(ctx, "DeregisterImage", image, nil); err != nil {
		return nil, err
	}
	if boolValue(in.DeleteAssociatedSnapshots) {
		// TODO: Comeback support per-snapshot deletion outcomes after deregistration.
		return nil, unsupported("DeleteAssociatedSnapshots is not implemented; delete snapshots explicitly after deregistering their images.")
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if str(image.Data.DeregistrationProtection) == "enabled" {
		return nil, failure("OperationNotPermitted", "The image has deregistration protection enabled.")
	}
	// Retain a lightweight known-ID tombstone, not active snapshot references.
	// DescribeImages omits it; repeated deregistration reports Unavailable.
	image.Data.State = new(api.ImageState("deregistered"))
	image.Data.BlockDeviceMappings = nil
	image.Data.Tags = nil
	image.LaunchPermissions = nil
	image.SnapshotOwners = nil
	if err := tx.PutImage(image); err != nil {
		return nil, err
	}
	return &api.DeregisterImageResult{Return: new(api.Boolean(true)), DeleteSnapshotResults: api.DeleteSnapshotResultSet{}}, nil
}

// Keep error conversion at the image boundary; snapshot APIs use a different
// historical NotFound spelling than RegisterImage.
func imageSnapshotError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return failure("InvalidSnapshotID.NotFound", "The snapshot does not exist")
	}
	var wire *awswire.Error
	if errors.As(err, &wire) && wire.Code == "InvalidSnapshot.NotFound" {
		return failure("InvalidSnapshotID.NotFound", wire.Message)
	}
	return err
}
