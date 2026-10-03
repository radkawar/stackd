package ec2

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

func (s *Service) authorizeInstanceVolume(ctx context.Context, action, id string) error {
	if s.volumes == nil || s.instanceVolumes == nil {
		return unsupported("The EBS instance volume owner is not configured.")
	}
	_, request, err := s.volumes.VolumeTags(ctx, action, id)
	if err != nil {
		return err
	}
	now := s.clock.Now()
	request.EvaluationTime = &now
	if denied := s.authorizer.Authorize(ctx, request); denied != nil {
		return denied
	}
	return nil
}

func attachmentDeviceName(value string) (string, error) {
	name := strings.TrimPrefix(value, "/dev/")
	suffix := ""
	switch {
	case strings.HasPrefix(name, "xvd"):
		suffix = strings.TrimPrefix(name, "xvd")
	case strings.HasPrefix(name, "sd"):
		suffix = strings.TrimPrefix(name, "sd")
	default:
		return "", failure("InvalidParameterValue", "The requested Linux EBS device name is invalid.")
	}
	if len(suffix) < 1 || len(suffix) > 3 {
		return "", failure("InvalidParameterValue", "The requested Linux EBS device name is invalid.")
	}
	if suffix[0] < 'a' || suffix[0] > 'z' {
		return "", failure("InvalidParameterValue", "The requested Linux EBS device name is invalid.")
	}
	for _, c := range suffix[1:] {
		if c < '0' || c > '9' {
			return "", failure("InvalidParameterValue", "The requested Linux EBS device name is invalid.")
		}
	}
	return suffix, nil
}

func volumeAttachment(instance api.Instance, mapping api.InstanceBlockDeviceMapping) *api.VolumeAttachment {
	return &api.VolumeAttachment{InstanceId: instance.InstanceId, VolumeId: mapping.Ebs.VolumeId, Device: mapping.DeviceName, State: new(api.VolumeAttachmentState(str(mapping.Ebs.Status))), AttachTime: mapping.Ebs.AttachTime, DeleteOnTermination: mapping.Ebs.DeleteOnTermination, EbsCardIndex: mapping.Ebs.EbsCardIndex}
}

func (s *Service) attachVolume(ctx context.Context, tx Transaction, in *api.AttachVolumeRequest) (*api.VolumeAttachment, error) {
	records, err := s.instanceCommandTargets(ctx, tx, "AttachVolume", api.InstanceIdStringList{api.InstanceId(str(in.InstanceId))}, nil)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeInstanceVolume(ctx, "AttachVolume", str(in.VolumeId)); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	record := records[0]
	if state := instanceState(record); state != "running" && state != "stopped" {
		return nil, failure("IncorrectState", "Volumes can only be attached to running or stopped instances.")
	}
	if in.EbsCardIndex != nil && *in.EbsCardIndex != 0 {
		return nil, unsupported("Multiple EBS cards are not supported by the native backend.")
	}
	device, err := attachmentDeviceName(str(in.Device))
	if err != nil {
		return nil, err
	}
	for _, mapping := range record.Data.BlockDeviceMappings {
		if mapping.Ebs != nil && str(mapping.Ebs.VolumeId) == str(in.VolumeId) {
			return nil, failure("VolumeInUse", "The volume is already attached to this instance.")
		}
		existing, _ := attachmentDeviceName(str(mapping.DeviceName))
		if existing == device {
			return nil, failure("InvalidParameterValue", "The specified device is already in use.")
		}
	}
	// This is a backend topology limit, not guessed AWS instance-type capacity.
	if len(record.Data.BlockDeviceMappings) >= 28 {
		return nil, unsupported("The native backend has no available NVMe attachment slot.")
	}
	mapping := api.InstanceBlockDeviceMapping{DeviceName: in.Device, Ebs: &api.EbsInstanceBlockDevice{VolumeId: new(api.String(str(in.VolumeId))), Status: new(api.AttachmentStatus("attaching")), DeleteOnTermination: new(api.Boolean(false)), AttachTime: new(api.DateTime(s.clock.Now())), EbsCardIndex: new(api.Integer(0))}}
	if err := s.instanceVolumes.AdmitInstanceVolumeAttachment(ctx, record.Data, mapping); err != nil {
		return nil, err
	}
	record.Data.BlockDeviceMappings = append(record.Data.BlockDeviceMappings, mapping)
	record.Generation++
	scheduleInstanceObservation(&record, s.clock.Now())
	setInstanceCommand(ctx, &record)
	if err := tx.PutInstance(record); err != nil {
		return nil, err
	}
	return volumeAttachment(record.Data, mapping), nil
}

func (s *Service) detachVolume(ctx context.Context, tx Transaction, in *api.DetachVolumeRequest) (*api.VolumeAttachment, error) {
	if err := s.authorizeInstanceVolume(ctx, "DetachVolume", str(in.VolumeId)); err != nil {
		return nil, err
	}
	var record InstanceRecord
	index := -1
	if str(in.InstanceId) != "" {
		var err error
		record, err = loadInstance(ctx, tx, str(in.InstanceId))
		if err != nil {
			return nil, err
		}
		for i, mapping := range record.Data.BlockDeviceMappings {
			if mapping.Ebs != nil && str(mapping.Ebs.VolumeId) == str(in.VolumeId) {
				index = i
				break
			}
		}
	} else {
		records, err := tx.Instances(scopeFor(ctx))
		if err != nil {
			return nil, err
		}
		for _, candidate := range records {
			for i, mapping := range candidate.Data.BlockDeviceMappings {
				if mapping.Ebs != nil && str(mapping.Ebs.VolumeId) == str(in.VolumeId) {
					record = candidate
					index = i
					break
				}
			}
			if index >= 0 {
				break
			}
		}
	}
	if index >= 0 {
		if err := s.authorize(ctx, "DetachVolume", "instance", record.Key.ID, record.Data.Tags); err != nil {
			return nil, err
		}
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if index < 0 {
		return nil, failure("IncorrectState", "The volume is not attached to the specified instance.")
	}
	mapping := &record.Data.BlockDeviceMappings[index]
	if in.Device != nil && str(in.Device) != str(mapping.DeviceName) {
		return nil, failure("InvalidAttachment.NotFound", "The specified volume attachment does not exist.")
	}
	state := instanceState(record)
	if state != "running" && state != "stopped" {
		return nil, failure("IncorrectState", "The instance is not in a state from which a volume can be detached.")
	}
	if str(mapping.DeviceName) == str(record.Data.RootDeviceName) && state != "stopped" {
		return nil, failure("IncorrectState", "The root volume cannot be detached from a running instance.")
	}
	if boolValue(in.Force) && state != "stopped" {
		// A guest-unacknowledged device_del is not completed detachment.
		return nil, unsupported("Forced live detachment is not supported by the native backend.")
	}
	if str(mapping.Ebs.Status) != "detaching" {
		mapping.Ebs.Status = new(api.AttachmentStatus("detaching"))
		record.Generation++
		scheduleInstanceObservation(&record, s.clock.Now())
		setInstanceCommand(ctx, &record)
		if err := tx.PutInstance(record); err != nil {
			return nil, err
		}
	}
	return volumeAttachment(record.Data, *mapping), nil
}
