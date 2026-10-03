package ebs

import (
	"context"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/ec2"
)

// VolumeInitializationDelay is the local publication delay for already hydrated
// snapshot-backed disks, not a measurement of AWS initialization throughput.
const VolumeInitializationDelay = 2 * time.Second

func volumeStatusID(id string) error {
	if !strings.HasPrefix(id, "vol-") {
		return ec2Failure("InvalidVolumeID.Malformed", "Invalid id: \""+id+"\" (expecting \"vol-...\")")
	}
	if !validControlVolumeID(id) {
		return ec2Failure("InvalidVolumeID.Malformed", "Invalid id: \""+id+"\"")
	}
	return nil
}

func (s *Service) volumeStatusProjection(ctx context.Context, v VolumeRecord) (api.VolumeStatusItem, error) {
	out := api.VolumeStatusItem{
		VolumeId: new(api.String(v.Key.ID)), AvailabilityZone: new(api.String(v.ZoneName)), AvailabilityZoneId: new(api.String(v.ZoneID)),
		Actions: api.VolumeStatusActionsList{}, Events: api.VolumeStatusEventsList{},
		VolumeStatus: &api.VolumeStatusInfo{
			Status: new(api.VolumeStatusInfoStatusOk),
			Details: api.VolumeStatusDetailsList{
				{Name: new(api.VolumeStatusNameIo_enabled), Status: new(api.String("passed"))},
				{Name: new(api.VolumeStatusNameIo_performance), Status: new(api.String("not-applicable"))},
			},
		},
		Operator: &api.OperatorResponse{Managed: new(api.Boolean(false)), HiddenByDefault: new(api.Boolean(false))},
	}
	attachments, err := s.volumeAttachments(ctx, v)
	if err != nil {
		return api.VolumeStatusItem{}, err
	}
	for _, attachment := range attachments {
		out.AttachmentStatuses = append(out.AttachmentStatuses, api.VolumeStatusAttachmentStatus{
			InstanceId: attachment.InstanceId, IoPerformance: new(api.String("normal")),
		})
	}
	if v.SnapshotID != "" {
		state, progress := "initializing", api.Long(0)
		if v.Creation == nil && !s.clock.Now().Before(v.Created.Add(VolumeInitializationDelay)) {
			state, progress = "completed", 100
		}
		out.VolumeStatus.Details = append(out.VolumeStatus.Details, api.VolumeStatusDetails{
			Name: new(api.VolumeStatusNameInitialization_state), Status: new(api.String(state)),
		})
		out.InitializationStatusDetails = &api.InitializationStatusDetails{
			InitializationType: new(api.InitializationTypeDefault), Progress: new(progress),
		}
		if v.InitializationRate != 0 {
			out.InitializationStatusDetails.InitializationType = new(api.InitializationTypeProvisioned_rate)
			// Native provisioned-rate responses include zero while initializing;
			// this estimate is not a completion signal.
			out.InitializationStatusDetails.EstimatedTimeToCompleteInSeconds = new(api.Long(0))
		}
	}
	return out, nil
}

func (s *Service) DescribeVolumeStatus(ctx context.Context, in *api.DescribeVolumeStatusRequest) (*api.DescribeVolumeStatusResult, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	var out *api.DescribeVolumeStatusResult
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorizeVolume(r.Context(), "DescribeVolumeStatus", VolumeRecord{}, nil); err != nil {
			return err
		}
		if err := ec2DryRun(in.DryRun); err != nil {
			return err
		}
		request := in
		for _, id := range in.VolumeIds {
			if id == "" {
				normalized := *in
				normalized.VolumeIds = make(api.VolumeIdStringList, 0, len(in.VolumeIds))
				for _, candidate := range in.VolumeIds {
					if candidate != "" {
						normalized.VolumeIds = append(normalized.VolumeIds, candidate)
					}
				}
				request = &normalized
				break
			}
		}
		if len(request.VolumeIds) > 0 && (request.MaxResults != nil || value(request.NextToken) != "") {
			_, err := ec2.SelectVolumeStatusPage(r.Context(), request, nil)
			return err
		}
		var rows api.VolumeStatusList
		if len(request.VolumeIds) > 0 {
			rows = make(api.VolumeStatusList, 0, len(request.VolumeIds))
			var seen map[api.VolumeId]bool
			if len(request.VolumeIds) > 1 {
				seen = make(map[api.VolumeId]bool, len(request.VolumeIds))
			}
			for _, id := range request.VolumeIds {
				if seen[id] {
					continue
				}
				if seen != nil {
					seen[id] = true
				}
				if err := volumeStatusID(string(id)); err != nil {
					return err
				}
				v, err := ownedVolume(r, string(id))
				if err != nil {
					return err
				}
				if v.Status == api.VolumeStateDeleting {
					return volumeMissing(v.Key.ID)
				}
				if v.StateMessage == "" {
					row, err := s.volumeStatusProjection(r.Context(), v)
					if err != nil {
						return err
					}
					rows = append(rows, row)
				}
			}
			// IDs were resolved above. A failed creating volume has no healthy
			// status row while its terminal disappearance is still scheduled.
			selection := *request
			selection.VolumeIds = nil
			request = &selection
		} else {
			records, err := r.Volumes(scopeFor(r.Context()))
			if err != nil {
				return err
			}
			rows = make(api.VolumeStatusList, 0, len(records))
			for _, v := range records {
				if v.Status != api.VolumeStateDeleted && v.Status != api.VolumeStateDeleting && v.StateMessage == "" {
					row, err := s.volumeStatusProjection(r.Context(), v)
					if err != nil {
						return err
					}
					rows = append(rows, row)
				}
			}
		}
		selected, err := ec2.SelectVolumeStatusPage(r.Context(), request, rows)
		out = selected
		return err
	})
	return out, err
}
