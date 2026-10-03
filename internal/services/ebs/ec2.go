package ebs

import (
	"context"
	"errors"
	"slices"

	"stackd/internal/authorization"
	ebsapi "stackd/internal/awsapi/ebs"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
	ec2 "stackd/internal/services/ec2"
)

var _ ec2.SnapshotControl = (*Service)(nil)

func ec2Failure(code, message string) *awswire.Error { return failure(code, message, "", 400) }
func ec2DryRun(dry *api.Boolean) error {
	if dry != nil && bool(*dry) {
		return failure("DryRunOperation", "Request would have succeeded, but DryRun flag is set.", "", 412)
	}
	return nil
}
func ec2SnapshotMissing(id string) *awswire.Error {
	return ec2Failure("InvalidSnapshot.NotFound", "The snapshot '"+id+"' does not exist.")
}
func (s *Service) ec2Snapshot(r Reader, id string) (SnapshotRecord, error) {
	scope := scopeFor(r.Context())
	v, err := r.RegionalSnapshot(scope.Partition, scope.Region, id)
	if errors.Is(err, ErrNotFound) {
		return SnapshotRecord{}, ec2SnapshotMissing(id)
	}
	if err != nil {
		return SnapshotRecord{}, err
	}
	s.observeSnapshot(r.Context(), v)
	if v.Deleted {
		return SnapshotRecord{}, ec2SnapshotMissing(id)
	}
	return v, nil
}

func snapshotProjection(v *SnapshotRecord) api.Snapshot {
	row := api.Snapshot{SnapshotId: new(api.String(v.Key.ID)), OwnerId: new(api.String(v.Key.AccountID)), StartTime: new(v.Created), Description: new(api.String(v.Description)), VolumeSize: new(api.Integer(v.VolumeSize)), VolumeId: new(api.String("vol-ffffffff")), State: new(api.SnapshotState(v.Status)), Progress: new(api.String("0%")), Encrypted: new(api.Boolean(v.KMSKeyARN != "")), StorageTier: new(api.StorageTier("standard")), TransferType: new(api.TransferType("standard")), Tags: ec2Tags(v.Tags)}
	if v.Volume != nil {
		row.VolumeId = new(api.String(v.Volume.Source.ID))
	}
	if v.KMSKeyARN != "" {
		row.KmsKeyId = new(api.String(v.KMSKeyARN))
	}
	if v.Copy != nil && v.Copy.CompletionDurationMinutes != 0 {
		row.TransferType = new(api.TransferType("time-based"))
		row.CompletionDurationMinutes = new(api.SnapshotCompletionDurationMinutesResponse(v.Copy.CompletionDurationMinutes))
	}
	if v.Status == ebsapi.StatusERROR {
		row.StateMessage = new(api.String(v.StateMessage))
	}
	if v.Status == ebsapi.StatusCOMPLETED {
		row.CompletionTime = new(v.CompleteAt)
		row.Progress = new(api.String("100%"))
	}
	return row
}
func (s *Service) DescribeSnapshots(ctx context.Context, in *api.DescribeSnapshotsRequest) (*api.DescribeSnapshotsResult, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	var out *api.DescribeSnapshotsResult
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorize(r.Context(), "ec2", "DescribeSnapshots", SnapshotRecord{}, nil); err != nil {
			return err
		}
		if err := ec2DryRun(in.DryRun); err != nil {
			return err
		}
		scope := scopeFor(r.Context())
		records, err := r.AvailableSnapshots(scope)
		if err != nil {
			return err
		}
		rows := api.SnapshotList{}
		var restorable map[string]bool
		if len(in.RestorableByUserIds) > 0 {
			restorable = make(map[string]bool, len(records))
		}
		for _, v := range records {
			visible, err := s.ec2Visible(r, v)
			if err != nil {
				return err
			}
			if !visible {
				continue
			}
			// Explicit IDs see current EC2 grants; discovery waits for their
			// publication, while effective public access is immediately visible.
			if len(in.SnapshotIds) == 0 && v.Key.AccountID != scope.AccountID {
				share, ok := snapshotShare(v, scope.AccountID)
				if !ok || !share.Readable {
					if !v.Public {
						continue
					}
					state, _, _, err := s.effectivePublicAccess(r, v.Key.Scope)
					if err != nil {
						return err
					}
					if state == "block-all-sharing" {
						continue
					}
				}
			}
			if len(in.RestorableByUserIds) > 0 {
				match, err := s.snapshotRestorable(r, v, in.RestorableByUserIds)
				if err != nil {
					return err
				}
				if match {
					restorable[v.Key.ID] = true
				}
			}
			if v.Key.AccountID != scope.AccountID {
				v.Tags, err = r.SharedTags(SharedTagsKey{Snapshot: v.Key, AccountID: scope.AccountID})
				if err != nil {
					return err
				}
			}
			row := snapshotProjection(&v)
			if v.Status == ebsapi.StatusCOMPLETED {
				blocks, err := resolvedBlocks(r, v)
				if err != nil {
					return err
				}
				row.FullSnapshotSizeInBytes = new(api.Long(int64(len(blocks)) * BlockSize))
			}
			rows = append(rows, row)
		}
		out, err = ec2.SelectSnapshotPage(r.Context(), in, rows, restorable)
		return err
	})
	return out, err
}
func (s *Service) snapshotRestorable(r Reader, v SnapshotRecord, selectors api.RestorableByStringList) (bool, error) {
	account := scopeFor(r.Context()).AccountID
	for _, selector := range selectors {
		target := string(selector)
		if target == "all" {
			if !v.Public {
				continue
			}
			state, _, _, err := s.effectivePublicAccess(r, v.Key.Scope)
			if err != nil {
				return false, err
			}
			if state != "block-all-sharing" {
				return true, nil
			}
			continue
		}
		if target == "self" {
			target = account
		}
		if target != account && v.Key.AccountID != account {
			continue
		}
		if target == v.Key.AccountID {
			return true, nil
		}
		if share, ok := snapshotShare(v, target); ok && share.Readable {
			return true, nil
		}
	}
	return false, nil
}
func (s *Service) DeleteSnapshot(ctx context.Context, in *api.DeleteSnapshotRequest) (*api.Unit, error) {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.ec2Snapshot(tx, value(in.SnapshotId))
		if err != nil {
			return err
		}
		if err = s.authorize(tx.Context(), "ec2", "DeleteSnapshot", v, nil); err != nil {
			return err
		}
		if err = ec2DryRun(in.DryRun); err != nil {
			return err
		}
		if v.Key.AccountID != scopeFor(tx.Context()).AccountID {
			return ec2SnapshotMissing(v.Key.ID)
		}
		if s.images != nil {
			imageID, err := s.images.ImageReferencingSnapshot(tx.Context(), v.Key.AccountID, v.Key.ID)
			if err != nil {
				return err
			}
			if imageID != "" {
				return ec2Failure("InvalidSnapshot.InUse", "The snapshot "+v.Key.ID+" is currently in use by "+imageID)
			}
		}
		v.Deleted = true
		v.DeleteAt = s.clock.Now().Add(DeletionDelay)
		return tx.PutSnapshot(v)
	})
	if err != nil {
		return nil, err
	}
	s.jobs.Wake()
	return &api.Unit{}, nil
}
func ec2Tags(tags map[string]string) api.TagList {
	if len(tags) == 0 {
		return nil
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make(api.TagList, 0, len(keys))
	for _, k := range keys {
		out = append(out, api.Tag{Key: new(api.String(k)), Value: new(api.String(tags[k]))})
	}
	return out
}
func (s *Service) SnapshotTags(ctx context.Context, action, id string) (api.TagList, authorization.Request, error) {
	if err := s.advance(ctx); err != nil {
		return nil, authorization.Request{}, err
	}
	var tags api.TagList
	var request authorization.Request
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.ec2Snapshot(r, id)
		if err != nil {
			return err
		}
		if action == "CreateTags" {
			visible, err := s.ec2Visible(r, v)
			if err != nil {
				return err
			}
			if !visible {
				return ec2SnapshotMissing(id)
			}
		}
		if v.Key.AccountID != scopeFor(r.Context()).AccountID {
			v.Tags, err = r.SharedTags(SharedTagsKey{Snapshot: v.Key, AccountID: scopeFor(r.Context()).AccountID})
			if err != nil {
				return err
			}
		}
		tags = ec2Tags(v.Tags)
		request = s.authorizationRequest(r.Context(), "ec2", action, v, nil)
		return nil
	})
	return tags, request, err
}
func (s *Service) SetSnapshotTags(ctx context.Context, id string, tags api.TagList) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.ec2Snapshot(tx, id)
		if err != nil {
			return err
		}
		values := make(map[string]string, len(tags))
		for _, tag := range tags {
			values[value(tag.Key)] = value(tag.Value)
		}
		if v.Key.AccountID != scopeFor(tx.Context()).AccountID {
			return tx.PutSharedTags(SharedTagsKey{Snapshot: v.Key, AccountID: scopeFor(tx.Context()).AccountID}, values)
		}
		v.Tags = values
		return tx.PutSnapshot(v)
	})
}
func (s *Service) ListSnapshotTags(ctx context.Context) (api.TagDescriptionList, error) {
	out := api.TagDescriptionList{}
	err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.TagsForAccount(scopeFor(r.Context()))
		if err != nil {
			return err
		}
		for _, tag := range rows {
			out = append(out, api.TagDescription{ResourceId: new(api.String(tag.Snapshot.ID)), ResourceType: new(api.ResourceType("snapshot")), Key: new(api.String(tag.Key)), Value: new(api.String(tag.Value))})
		}
		return nil
	})
	return out, err
}

func (s *Service) defaultControl(ctx context.Context, action string, dry *api.Boolean, change func(Transaction, *EncryptionDefault) error) (EncryptionDefault, error) {
	var v EncryptionDefault
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx.Context(), "ec2", action, SnapshotRecord{}, nil); err != nil {
			return err
		}
		if err := ec2DryRun(dry); err != nil {
			return err
		}
		var err error
		v, err = s.encryptionDefault(tx)
		if err != nil {
			return err
		}
		if change != nil {
			if err = change(tx, &v); err != nil {
				return err
			}
			return tx.PutEncryptionDefault(v)
		}
		return nil
	})
	return v, err
}
func (s *Service) GetEbsEncryptionByDefault(ctx context.Context, in *api.GetEbsEncryptionByDefaultRequest) (*api.GetEbsEncryptionByDefaultResult, error) {
	v, err := s.defaultControl(ctx, "GetEbsEncryptionByDefault", in.DryRun, nil)
	if err != nil {
		return nil, err
	}
	return &api.GetEbsEncryptionByDefaultResult{EbsEncryptionByDefault: new(api.Boolean(v.Enabled))}, nil
}
func (s *Service) EnableEbsEncryptionByDefault(ctx context.Context, in *api.EnableEbsEncryptionByDefaultRequest) (*api.EnableEbsEncryptionByDefaultResult, error) {
	v, err := s.defaultControl(ctx, "EnableEbsEncryptionByDefault", in.DryRun, func(_ Transaction, v *EncryptionDefault) error { v.Enabled = true; return nil })
	if err != nil {
		return nil, err
	}
	return &api.EnableEbsEncryptionByDefaultResult{EbsEncryptionByDefault: new(api.Boolean(v.Enabled))}, nil
}
func (s *Service) DisableEbsEncryptionByDefault(ctx context.Context, in *api.DisableEbsEncryptionByDefaultRequest) (*api.DisableEbsEncryptionByDefaultResult, error) {
	v, err := s.defaultControl(ctx, "DisableEbsEncryptionByDefault", in.DryRun, func(_ Transaction, v *EncryptionDefault) error { v.Enabled = false; return nil })
	if err != nil {
		return nil, err
	}
	return &api.DisableEbsEncryptionByDefaultResult{EbsEncryptionByDefault: new(api.Boolean(v.Enabled))}, nil
}
func (s *Service) GetEbsDefaultKmsKeyId(ctx context.Context, in *api.GetEbsDefaultKmsKeyIdRequest) (*api.GetEbsDefaultKmsKeyIdResult, error) {
	v, err := s.defaultControl(ctx, "GetEbsDefaultKmsKeyId", in.DryRun, nil)
	if err != nil {
		return nil, err
	}
	key := v.KMSKeyID
	if key == "" {
		key = "alias/aws/ebs"
	}
	return &api.GetEbsDefaultKmsKeyIdResult{KmsKeyId: new(api.String(key))}, nil
}
func (s *Service) ModifyEbsDefaultKmsKeyId(ctx context.Context, in *api.ModifyEbsDefaultKmsKeyIdRequest) (*api.ModifyEbsDefaultKmsKeyIdResult, error) {
	v, err := s.defaultControl(ctx, "ModifyEbsDefaultKmsKeyId", in.DryRun, func(tx Transaction, v *EncryptionDefault) error {
		if value(in.KmsKeyId) == "" {
			return ec2Failure("InvalidParameterValue", "The KMS key ID is invalid.")
		}
		key, err := s.defaultKey(tx.Context(), value(in.KmsKeyId))
		if err != nil {
			return err
		}
		// TODO: Comeback calibrate native asynchronous default-key admission.
		arn, rejected := s.keys.DescribeKey(tx.Context(), key)
		if rejected != nil {
			return ec2Failure("InvalidParameterValue", rejected.Message)
		}
		v.KMSKeyID = arn
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &api.ModifyEbsDefaultKmsKeyIdResult{KmsKeyId: new(api.String(v.KMSKeyID))}, nil
}
func (s *Service) ResetEbsDefaultKmsKeyId(ctx context.Context, in *api.ResetEbsDefaultKmsKeyIdRequest) (*api.ResetEbsDefaultKmsKeyIdResult, error) {
	v, err := s.defaultControl(ctx, "ResetEbsDefaultKmsKeyId", in.DryRun, func(tx Transaction, v *EncryptionDefault) error {
		var err error
		v.KMSKeyID, err = s.defaultKey(tx.Context(), "alias/aws/ebs")
		return err
	})
	if err != nil {
		return nil, err
	}
	return &api.ResetEbsDefaultKmsKeyIdResult{KmsKeyId: new(api.String(v.KMSKeyID))}, nil
}
