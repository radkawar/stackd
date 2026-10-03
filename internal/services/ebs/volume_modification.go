package ebs

import (
	"context"
	"errors"
	"strings"
	"time"

	native "stackd/compute/ec2"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
)

// Deterministic local deadlines let callers advance the shared scheduler without
// assuming native EBS latency. Native empty-volume fixtures completed in two seconds.
const (
	// VolumeModificationOptimizingDelay is when target configuration takes effect.
	VolumeModificationOptimizingDelay = time.Second
	// VolumeModificationCompletionDelay is when another modification is admissible.
	VolumeModificationCompletionDelay = 2 * time.Second
)

func modifiedVolumeConfiguration(in *api.ModifyVolumeRequest, current VolumeConfiguration) (VolumeConfiguration, error) {
	if in.Size == nil && in.VolumeType == nil && in.Iops == nil && in.Throughput == nil && in.MultiAttachEnabled == nil {
		return VolumeConfiguration{}, ec2Failure("InvalidParameterValue", "Invalid input: Must specify at least one of size, type, iops, throughput or multi-attach.")
	}
	if current.MultiAttach && current.Type == "io1" {
		return VolumeConfiguration{}, ec2Failure("InvalidParameterValue", "io1 volumes with Multi-Attach enabled do not support modify-volume actions. Please review the EBS technical documentation for information on the Multi-Attach limitations and considerations.")
	}
	if in.Size != nil && int32(*in.Size) < current.Size {
		return VolumeConfiguration{}, ec2Failure("InvalidParameterValue", "New size cannot be smaller than existing size")
	}
	request := api.CreateVolumeRequest{
		Size: in.Size, VolumeType: in.VolumeType, Iops: in.Iops,
		Throughput: in.Throughput, MultiAttachEnabled: in.MultiAttachEnabled,
	}
	if request.Size == nil {
		request.Size = new(api.Integer(current.Size))
	}
	if request.VolumeType == nil || *request.VolumeType == "" {
		request.VolumeType = new(current.Type)
	}
	targetType := api.VolumeType(strings.ToLower(string(*request.VolumeType)))
	if request.Iops == nil && (targetType == "gp3" || targetType == "io1" || targetType == "io2") {
		iops := int32(3000)
		if targetType == current.Type {
			iops = current.Iops
		} else if targetType == "gp3" && current.Type == "gp2" {
			iops = max(3000, current.Iops)
		}
		request.Iops = new(api.Integer(iops))
	}
	if request.Throughput == nil && targetType == "gp3" {
		throughput := int32(125)
		if current.Type == "gp3" {
			throughput = current.Throughput
		} else if current.Type == "gp2" {
			// Match gp2's baseline performance above the gp3 baseline, up to
			// the gp2 throughput ceiling, when changing type without overrides.
			throughput = min(250, max(125, (current.Iops+3)/4))
		}
		request.Throughput = new(api.Integer(throughput))
	}
	if request.MultiAttachEnabled == nil {
		request.MultiAttachEnabled = new(api.Boolean(current.MultiAttach))
	}
	configuration, err := volumeConfiguration(&request, 0)
	if err != nil {
		return configuration, err
	}
	if err := volumeMultiAttachConfiguration(configuration); err != nil {
		return configuration, err
	}
	return configuration, nil
}

func (s *Service) ModifyVolume(ctx context.Context, in *api.ModifyVolumeRequest) (*api.ModifyVolumeResult, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	var checked VolumeRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		checked, err = s.volumeControl(r, "ModifyVolume", in.VolumeId, in.DryRun)
		if err != nil {
			return err
		}
		target, err := modifiedVolumeConfiguration(in, checked.Configuration)
		if err == nil && checked.NativePath != "" && target.MultiAttach {
			return ec2Failure("UnsupportedOperation", "Native shared-writer EBS Multi-Attach is not supported.")
		}
		return err
	}); err != nil {
		return nil, err
	}
	if checked.NativePath != "" && in.Size != nil && int32(*in.Size) != checked.Configuration.Size {
		if s.nativeDisks == nil {
			return nil, errors.New("native EBS disk storage is not configured")
		}
		if err := s.nativeDisks.CheckResizeDisk(ctx, nativeVolumeDisk(checked), int64(*in.Size)<<30); err != nil {
			var capability *native.CapabilityError
			if errors.As(err, &capability) {
				return nil, ec2Failure("UnsupportedOperation", capability.Error())
			}
			return nil, err
		}
	}
	var out *api.ModifyVolumeResult
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.volumeControl(tx, "ModifyVolume", in.VolumeId, in.DryRun)
		if err != nil {
			return err
		}
		if v.NativePath != checked.NativePath || v.Configuration != checked.Configuration {
			return ec2Failure("IncorrectState", "Volume changed while checking native resize capability.")
		}
		target, err := modifiedVolumeConfiguration(in, v.Configuration)
		if err != nil {
			return err
		}
		if v.Status != api.VolumeStateAvailable && v.Status != api.VolumeStateIn_use {
			return ec2Failure("IncorrectState", "Volume "+v.Key.ID+" must be in the available or in-use state to be modified.")
		}
		if m := v.Modification; m != nil && m.State != api.VolumeModificationStateCompleted && m.State != api.VolumeModificationStateFailed {
			return ec2Failure("IncorrectModificationState", "Volume "+v.Key.ID+" cannot be modified in modification state "+strings.ToUpper(string(m.State)))
		}
		now := s.clock.Now()
		cutoff := now.Add(-24 * time.Hour)
		starts := v.ModificationStarts[:0]
		for _, started := range v.ModificationStarts {
			if started.After(cutoff) {
				starts = append(starts, started)
			}
		}
		if len(starts) >= 4 {
			eligible := starts[0].Add(24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
			return ec2Failure("VolumeModificationRateExceeded", "You've reached the maximum modification rate per volume limit. Wait until "+eligible+" before you can issue the next modification request for this volume.")
		}
		v.ModificationStarts = append(starts, now)
		v.Modification = &VolumeModification{
			Original: v.Configuration, Target: target, Started: now,
			OptimizingAt: now.Add(VolumeModificationOptimizingDelay), CompletedAt: now.Add(VolumeModificationCompletionDelay),
			State:     api.VolumeModificationStateModifying,
			RequestID: awsctx.FromContext(tx.Context()).RequestID, ParentEventID: apievents.EventID(tx.Context()),
		}
		if err := tx.PutVolume(v); err != nil {
			return err
		}
		row := volumeModificationProjection(v, false)
		out = &api.ModifyVolumeResult{VolumeModification: &row}
		return ec2.RecordExternalSuccess(tx.Context(), out)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return out, err
}

func volumeModificationProjection(v VolumeRecord, described bool) api.VolumeModification {
	m := v.Modification
	out := api.VolumeModification{
		VolumeId: new(api.String(v.Key.ID)), ModificationState: new(m.State),
		OriginalSize: new(api.Integer(m.Original.Size)), TargetSize: new(api.Integer(m.Target.Size)),
		OriginalVolumeType: new(m.Original.Type), TargetVolumeType: new(m.Target.Type),
		OriginalMultiAttachEnabled: new(api.Boolean(m.Original.MultiAttach)), TargetMultiAttachEnabled: new(api.Boolean(m.Target.MultiAttach)),
		Progress: new(api.Long(0)), StartTime: new(m.Started.Truncate(time.Second)),
	}
	if m.StatusMessage != "" {
		out.StatusMessage = new(api.String(m.StatusMessage))
	}
	if m.State == api.VolumeModificationStateFailed {
		out.EndTime = new(m.CompletedAt.Truncate(time.Second))
	}
	if m.Original.Iops != 0 {
		out.OriginalIops = new(api.Integer(m.Original.Iops))
	}
	if m.Target.Iops != 0 {
		out.TargetIops = new(api.Integer(m.Target.Iops))
	}
	if m.Original.Throughput != 0 {
		out.OriginalThroughput = new(api.Integer(m.Original.Throughput))
	}
	if m.Target.Throughput != 0 {
		out.TargetThroughput = new(api.Integer(m.Target.Throughput))
	}
	if m.State == api.VolumeModificationStateOptimizing {
		out.Progress = new(api.Long(50))
	}
	if m.State == api.VolumeModificationStateCompleted {
		out.Progress = new(api.Long(100))
		out.EndTime = new(m.CompletedAt.Truncate(time.Second))
	}
	if described {
		out.Operator = &api.OperatorResponse{Managed: new(api.Boolean(false)), HiddenByDefault: new(api.Boolean(false))}
	}
	return out
}

func (s *Service) DescribeVolumesModifications(ctx context.Context, in *api.DescribeVolumesModificationsRequest) (*api.DescribeVolumesModificationsResult, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	var out *api.DescribeVolumesModificationsResult
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorizeVolume(r.Context(), "DescribeVolumesModifications", VolumeRecord{}, nil); err != nil {
			return err
		}
		if err := ec2DryRun(in.DryRun); err != nil {
			return err
		}
		if len(in.VolumeIds) > 0 && (in.MaxResults != nil || value(in.NextToken) != "") {
			_, err := ec2.SelectVolumeModificationPage(r.Context(), in, nil)
			return err
		}
		var rows api.VolumeModificationList
		if len(in.VolumeIds) > 0 {
			rows = make(api.VolumeModificationList, 0, len(in.VolumeIds))
			var seen map[api.VolumeId]bool
			if len(in.VolumeIds) > 1 {
				seen = make(map[api.VolumeId]bool, len(in.VolumeIds))
			}
			for _, id := range in.VolumeIds {
				if seen[id] {
					continue
				}
				if seen != nil {
					seen[id] = true
				}
				if err := controlVolumeID(new(api.VolumeId(id))); err != nil {
					return err
				}
				v, err := ownedVolume(r, string(id))
				if err != nil {
					return err
				}
				if v.Status == api.VolumeStateDeleting {
					return volumeMissing(v.Key.ID)
				}
				if v.Modification != nil {
					rows = append(rows, volumeModificationProjection(v, true))
				}
			}
		} else {
			records, err := r.Volumes(scopeFor(r.Context()))
			if err != nil {
				return err
			}
			rows = make(api.VolumeModificationList, 0, len(records))
			for _, v := range records {
				if v.Modification != nil && v.Status != api.VolumeStateDeleted && v.Status != api.VolumeStateDeleting {
					rows = append(rows, volumeModificationProjection(v, true))
				}
			}
		}
		selected, err := ec2.SelectVolumeModificationPage(r.Context(), in, rows)
		out = selected
		return err
	})
	return out, err
}
