package integrations

import (
	"context"
	"errors"
	"fmt"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

// cfnEC2VolumeAttachment owns the exact EC2 block-device slot volume|instance
// through EC2's private relation receipt, admitted atomically with the native
// AttachVolume. Any direct attach/detach of that slot invalidates the claim.
type cfnEC2VolumeAttachment struct{ commands StepFunctionsCommands }

func (h cfnEC2VolumeAttachment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "VolumeId", "InstanceId", "Device", "EbsCardIndex"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "VolumeId", "InstanceId"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "VolumeId", "InstanceId", "Device"); err != nil {
		return err
	}
	if cfnComputeString(p, "Device") == "" {
		return fmt.Errorf("device is required by the native EBS attachment owner")
	}
	return nil
}
func (h cfnEC2VolumeAttachment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "VolumeId", "InstanceId", "Device", "EbsCardIndex"), nil
}

// cfnEC2AttachmentID is the physical identifier recorded by the native receipt.
func cfnEC2AttachmentID(volume, instance string) string {
	return cfnEC2PairID(cloudformation.ResourceRequest{CloudControl: true}, volume, instance, "VolumeId", "InstanceId")
}
func cfnEC2AttachmentSlot(volume, instance string) string { return volume + "|" + instance }
func cfnEC2AttachmentIdentity(r cloudformation.ResourceRequest) (string, string, error) {
	if r.PhysicalID == "" {
		return "", "", fmt.Errorf("volume attachment physical identifier is required")
	}
	return cfnEC2Pair(r.PhysicalID, "VolumeId", "InstanceId")
}
func cfnEC2FindAttachment(v api.Volume, instance string) *api.VolumeAttachment {
	for i := range v.Attachments {
		if cfnComputeValue(v.Attachments[i].InstanceId) == instance && cfnComputeValue(v.Attachments[i].State) != "detached" {
			return &v.Attachments[i]
		}
	}
	return nil
}
func (h cfnEC2VolumeAttachment) live(ctx context.Context, volume, instance string) (*api.VolumeAttachment, error) {
	v, err := cfnEC2Volume(h).get(ctx, volume)
	if err != nil {
		return nil, err
	}
	return cfnEC2FindAttachment(v, instance), nil
}
func (h cfnEC2VolumeAttachment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	volume, instance := cfnComputeString(r.Properties, "VolumeId"), cfnComputeString(r.Properties, "InstanceId")
	id, slot := cfnEC2AttachmentID(volume, instance), cfnEC2AttachmentSlot(volume, instance)
	if r.PhysicalID != "" && r.PhysicalID != id {
		return cloudformation.ResourceResult{}, fmt.Errorf("volume attachment identity differs from the recovered physical resource")
	}
	if _, _, err := cfnEC2RelationReceipt(ctx, h.commands, r, slot); err == nil {
		recovered := r
		recovered.PhysicalID = id
		return h.RecoverCreation(ctx, recovered)
	} else if !errors.Is(err, ec2.ErrNotFound) {
		return cfnEC2IDResult(id), err
	}
	in := cfnComputeCopy(r.Properties, "VolumeId", "InstanceId", "Device", "EbsCardIndex")
	if _, err := cfnComputeCall[api.VolumeAttachment](cfnEC2RelationContext(ctx, r, slot), h.commands, "ec2", "AttachVolume", in); err != nil {
		r.PhysicalID = id
		return cfnEC2RelationFailedCreate(ctx, h.commands, r, h.RecoverCreation, err)
	}
	return cfnEC2IDResult(id), nil
}
func (h cfnEC2VolumeAttachment) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	volume, instance := cfnComputeString(r.Properties, "VolumeId"), cfnComputeString(r.Properties, "InstanceId")
	id := cfnEC2AttachmentID(volume, instance)
	liveID := ""
	a, err := h.live(ctx, volume, instance)
	if err != nil && !cfnEC2Missing(err) {
		return cfnEC2IDResult(id), err
	}
	if a != nil {
		if cfnComputeValue(a.Device) != cfnComputeString(r.Properties, "Device") {
			return cfnEC2IDResult(id), fmt.Errorf("volume attachment slot uses a different device")
		}
		liveID = id
	}
	return cfnEC2RelationRecover(ctx, h.commands, r, cfnEC2AttachmentSlot(volume, instance), liveID)
}

// owned observes the exact current admitted slot under current IAM and the live edge.
func (h cfnEC2VolumeAttachment) owned(ctx context.Context, r cloudformation.ResourceRequest) (*api.VolumeAttachment, error) {
	volume, instance, err := cfnEC2AttachmentIdentity(r)
	if err != nil {
		return nil, err
	}
	a, err := h.live(ctx, volume, instance)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, cfnEC2ComputeMissing("volume attachment", r.PhysicalID)
	}
	return a, cfnEC2RelationOwned(ctx, h.commands, r, cfnEC2AttachmentSlot(volume, instance), r.PhysicalID)
}
func (h cfnEC2VolumeAttachment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if changed, _ := h.Replacement(r.Previous, r.Properties); changed {
		return cloudformation.ResourceResult{}, fmt.Errorf("volume attachment update requires replacement")
	}
	if _, err := h.owned(ctx, r); err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	return cfnEC2IDResult(r.PhysicalID), nil
}

// Delete detaches only this incarnation's current slot. An invalidated slot is
// no longer this resource's edge and is never touched.
func (h cfnEC2VolumeAttachment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	volume, instance, err := cfnEC2AttachmentIdentity(r)
	if err != nil {
		return err
	}
	slot := cfnEC2AttachmentSlot(volume, instance)
	if !r.CloudControl {
		admitted, current, err := cfnEC2RelationReceipt(ctx, h.commands, r, slot)
		if errors.Is(err, ec2.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !current || admitted != r.PhysicalID {
			return nil
		}
	}
	a, err := h.live(ctx, volume, instance)
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if a == nil || cfnComputeValue(a.State) == "detaching" {
		return nil
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2RelationDeletionContext(ctx, r, slot), h.commands, "ec2", "DetachVolume", map[string]any{"VolumeId": volume, "InstanceId": instance, "Device": cfnComputeValue(a.Device)}))
}
func cfnEC2AttachmentProjection(a api.VolumeAttachment) cloudformation.Properties {
	p := cloudformation.Properties{"VolumeId": cfnComputeValue(a.VolumeId), "InstanceId": cfnComputeValue(a.InstanceId), "Device": cfnComputeValue(a.Device)}
	if a.EbsCardIndex != nil {
		p["EbsCardIndex"] = int64(*a.EbsCardIndex)
	}
	return p
}
func (h cfnEC2VolumeAttachment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	a, err := h.owned(ctx, r)
	if err != nil {
		return nil, err
	}
	return cfnEC2AttachmentProjection(*a), nil
}
func (h cfnEC2VolumeAttachment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := cfnEC2Volume(h).volumes(ctx, map[string]any{})
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, v := range rows {
		for _, a := range v.Attachments {
			if cfnComputeValue(a.State) == "detached" {
				continue
			}
			volume, instance := cfnComputeValue(v.VolumeId), cfnComputeValue(a.InstanceId)
			id := cfnEC2AttachmentID(volume, instance)
			if cfnEC2RelationOwned(ctx, h.commands, r, cfnEC2AttachmentSlot(volume, instance), id) != nil {
				continue
			}
			out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: cfnEC2AttachmentProjection(a)})
		}
	}
	return out, nil
}
func (h cfnEC2VolumeAttachment) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	a, err := h.owned(ctx, r)
	if err != nil {
		return false, err
	}
	switch cfnComputeValue(a.State) {
	case "attached":
		return true, nil
	case "attaching":
		return false, nil
	default:
		return false, fmt.Errorf("volume attachment entered %s", cfnComputeValue(a.State))
	}
}
func (h cfnEC2VolumeAttachment) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	volume, instance, err := cfnEC2AttachmentIdentity(r)
	if err != nil {
		return false, err
	}
	a, err := h.live(ctx, volume, instance)
	if cfnEC2Missing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	// A pending detach completes in the instance owner; any other live edge on
	// the slot is not this incarnation's (Delete fenced it) and is left intact.
	return a == nil || cfnComputeValue(a.State) != "detaching", nil
}
