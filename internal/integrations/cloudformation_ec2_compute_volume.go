package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

// cfnEC2Volume owns standalone EBS volumes through the EBS private native
// claim and creation receipt; public tags are customer metadata only.
type cfnEC2Volume struct{ commands StepFunctionsCommands }

func (h cfnEC2Volume) Validate(p cloudformation.Properties) error {
	if err := cfnEC2ComputeValidate(p, "AutoEnableIO", "AvailabilityZone", "AvailabilityZoneId", "Encrypted", "Iops", "KmsKeyId", "MultiAttachEnabled", "OutpostArn", "Size", "SnapshotId", "SourceVolumeId", "Tags", "Throughput", "VolumeInitializationRate", "VolumeType"); err != nil {
		return err
	}
	if p["SourceVolumeId"] != nil {
		return fmt.Errorf("SourceVolumeId requires EC2 CopyVolumes, which the EBS owner does not implement")
	}
	if (p["AvailabilityZone"] == nil) == (p["AvailabilityZoneId"] == nil) {
		return fmt.Errorf("specify exactly one of AvailabilityZone and AvailabilityZoneId")
	}
	if p["Size"] == nil && p["SnapshotId"] == nil {
		return fmt.Errorf("size or SnapshotId is required")
	}
	if err := cfnEC2Booleans(p, "AutoEnableIO", "Encrypted", "MultiAttachEnabled"); err != nil {
		return err
	}
	if _, err := cfnEC2NetworkTags(p); err != nil {
		return err
	}
	return cfnComputeStrings(p, "AvailabilityZone", "AvailabilityZoneId", "KmsKeyId", "OutpostArn", "SnapshotId", "VolumeType")
}
func (h cfnEC2Volume) Replacement(a, b cloudformation.Properties) (bool, error) {
	if cfnComputeChanged(a, b, "AvailabilityZone", "AvailabilityZoneId", "Encrypted", "KmsKeyId", "SnapshotId") {
		return false, fmt.Errorf("EC2 Volume availability zone, encryption, KMS key and snapshot updates are not supported")
	}
	if cfnComputeChanged(a, b, "MultiAttachEnabled", "OutpostArn", "SourceVolumeId", "VolumeInitializationRate") {
		return false, fmt.Errorf("the EBS owner cannot modify the requested volume creation attributes")
	}
	return false, nil
}
func (h cfnEC2Volume) volumes(ctx context.Context, in map[string]any) ([]api.Volume, error) {
	rows := []api.Volume{}
	for {
		out, err := cfnComputeCall[api.DescribeVolumesResult](ctx, h.commands, "ec2", "DescribeVolumes", in)
		if err != nil {
			return nil, err
		}
		rows = append(rows, out.Volumes...)
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		in["NextToken"] = *out.NextToken
	}
}
func (h cfnEC2Volume) get(ctx context.Context, id string) (api.Volume, error) {
	rows, err := h.volumes(ctx, map[string]any{"VolumeIds": []string{id}})
	if err != nil {
		return api.Volume{}, err
	}
	if len(rows) != 1 {
		return api.Volume{}, cfnEC2ComputeMissing("volume", id)
	}
	return rows[0], nil
}

// owned observes the live volume, then its exact private claim under current IAM.
func (h cfnEC2Volume) owned(ctx context.Context, r cloudformation.ResourceRequest) (api.Volume, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return v, err
	}
	return v, cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VolumeId))
}
func cfnEC2VolumeResult(v api.Volume) cloudformation.ResourceResult {
	id := cfnComputeValue(v.VolumeId)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"VolumeId": id}}
}
func (h cfnEC2Volume) autoIO(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnEC2NativeContext(ctx, r, "mutate")
	if value, found := r.Properties["AutoEnableIO"]; found {
		return cfnComputeRun(ctx, h.commands, "ec2", "ModifyVolumeAttribute", map[string]any{"VolumeId": r.PhysicalID, "AutoEnableIO": map[string]any{"Value": value}})
	}
	if r.Previous["AutoEnableIO"] != nil {
		return cfnComputeRun(ctx, h.commands, "ec2", "ModifyVolumeAttribute", map[string]any{"VolumeId": r.PhysicalID, "AutoEnableIO": map[string]any{"Value": false}})
	}
	return nil
}

// Create replays only this incarnation's private creation receipt. The native
// owner atomically admits the claim and receipt with the newly allocated volume.
func (h cfnEC2Volume) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if id == "" {
		in := cfnComputeCopy(r.Properties, "AvailabilityZone", "AvailabilityZoneId", "Encrypted", "Iops", "KmsKeyId", "MultiAttachEnabled", "OutpostArn", "Size", "SnapshotId", "Throughput", "VolumeInitializationRate", "VolumeType")
		in["ClientToken"] = cfnComputeHash(cfnEC2NativeIdentity(r))
		in["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "volume")
		v, err := cfnComputeCall[api.Volume](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateVolume", in)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		id = cfnComputeValue(v.VolumeId)
		if id == "" {
			return cloudformation.ResourceResult{}, fmt.Errorf("CreateVolume returned no volume ID")
		}
	}
	r.PhysicalID = id
	v, err := h.owned(ctx, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	result := cfnEC2VolumeResult(v)
	return result, h.autoIO(ctx, r)
}
func (h cfnEC2Volume) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	result := cfnEC2IDResult(id)
	if err != nil || id == "" {
		if err == nil {
			err = cfnEC2NotFound(r.Type)
		}
		return result, err
	}
	r.PhysicalID = id
	v, err := h.owned(ctx, r)
	if err != nil {
		return result, err
	}
	return cfnEC2VolumeResult(v), nil
}
func (h cfnEC2Volume) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if _, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.owned(ctx, r)
	result := cfnEC2VolumeResult(v)
	if err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	if err := h.modify(ctx, r, v); err != nil {
		return result, err
	}
	if err := h.autoIO(ctx, r); err != nil {
		return result, err
	}
	return result, cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, cfnEC2Tags(v.Tags))
}
func (h cfnEC2Volume) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.owned(ctx, r)
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if r.DeletionPolicy == "Snapshot" {
		ready, err := h.deletionSnapshot(ctx, r, v)
		if err != nil || !ready {
			return err
		}
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteVolume", map[string]any{"VolumeId": r.PhysicalID}))
}
func (h cfnEC2Volume) projection(ctx context.Context, v api.Volume) (cloudformation.Properties, error) {
	p, err := cfnEC2ComputeProjection(v)
	if err != nil {
		return nil, err
	}
	p = cloudformation.Properties(cfnComputeCopy(p, "VolumeId", "AvailabilityZone", "AvailabilityZoneId", "Encrypted", "Iops", "KmsKeyId", "MultiAttachEnabled", "OutpostArn", "Size", "SnapshotId", "SourceVolumeId", "Throughput", "VolumeInitializationRate", "VolumeType"))
	p["Tags"] = cfnEC2NetworkUserTags(v.Tags)
	out, err := cfnComputeCall[api.DescribeVolumeAttributeResult](ctx, h.commands, "ec2", "DescribeVolumeAttribute", map[string]any{"VolumeId": cfnComputeValue(v.VolumeId), "Attribute": "autoEnableIO"})
	if err != nil {
		return nil, err
	}
	if out.AutoEnableIO != nil {
		p["AutoEnableIO"] = cfnEC2ComputeBool(out.AutoEnableIO.Value)
	}
	return p, nil
}
func (h cfnEC2Volume) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.owned(ctx, r)
	if err != nil {
		return nil, err
	}
	return h.projection(ctx, v)
}
func (h cfnEC2Volume) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.volumes(ctx, map[string]any{})
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, v := range rows {
		if cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.VolumeId)) != nil {
			continue
		}
		p, err := h.projection(ctx, v)
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.VolumeId), Properties: p})
	}
	return out, nil
}
func (h cfnEC2Volume) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.owned(ctx, r)
	if err != nil {
		return false, err
	}
	state := cfnComputeValue(v.State)
	if state == "error" || state == "deleted" || state == "deleting" {
		return false, fmt.Errorf("EBS volume is %s", state)
	}
	if state != "available" && state != "in-use" {
		return false, nil
	}
	if cfnComputeChanged(r.Previous, r.Properties, "Size", "Iops", "Throughput", "VolumeType") && len(r.Previous) != 0 {
		out, err := cfnComputeCall[api.DescribeVolumesModificationsResult](ctx, h.commands, "ec2", "DescribeVolumesModifications", map[string]any{"VolumeIds": []string{r.PhysicalID}})
		if err != nil {
			return false, err
		}
		for _, m := range out.VolumesModifications {
			switch cfnComputeValue(m.ModificationState) {
			case "failed":
				return false, fmt.Errorf("EBS modification failed: %s", cfnComputeValue(m.StatusMessage))
			case "modifying", "optimizing":
				return false, nil
			}
		}
	}
	return true, nil
}

// StabilizeDeletion observes the volume row directly: a deleting volume no
// longer certifies a live claim, but its admitted deletion is still awaited.
func (h cfnEC2Volume) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if cfnEC2Missing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	state := cfnComputeValue(v.State)
	if state == "deleted" {
		return true, nil
	}
	if state == "deleting" {
		return false, nil
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return false, err
	}
	if r.DeletionPolicy == "Snapshot" {
		ready, err := h.deletionSnapshot(ctx, r, v)
		if err != nil || !ready {
			return false, err
		}
		err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteVolume", map[string]any{"VolumeId": r.PhysicalID})
		if cfnEC2Missing(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
	return false, nil
}
