package ebs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"stackd/internal/apievents"
	ebsapi "stackd/internal/awsapi/ebs"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
)

// CopySnapshot creates an independent block layer while preserving snapshot
// lineage. Source permissions authorize the transfer, not future use of the copy.
func (s *Service) CopySnapshot(ctx context.Context, in *api.CopySnapshotRequest) (*api.CopySnapshotResult, error) {
	if in.SourceSnapshotId == nil {
		return nil, ec2Failure("MissingParameter", "The request must contain the parameter SourceSnapshotId")
	}
	if err := snapshotControlID(value(in.SourceSnapshotId), false); err != nil {
		return nil, ec2Failure("InvalidParameterValue", "The specified snapshotId is invalid")
	}
	if in.SourceRegion == nil {
		return nil, failure("InternalError", "An internal error has occurred", "", 500)
	}
	scope := scopeFor(ctx)
	sourceRegion := value(in.SourceRegion)
	if awscatalog.RegionPartition(sourceRegion) != scope.Partition {
		return nil, ec2Failure("InvalidRegion", sourceRegion+" is not a valid region name.")
	}
	if in.CompletionDurationMinutes != nil {
		duration := int32(*in.CompletionDurationMinutes)
		if duration < 15 || duration > 2880 || duration%15 != 0 {
			return nil, ec2Failure("InvalidParameterValue", fmt.Sprintf("'%d' is not a valid value for completion duration. Specify a value between 15 and 2880 minutes, in 15 minute increments only", duration))
		}
	}
	tags, err := ec2.CreationTags(in.TagSpecifications, "snapshot")
	if err != nil {
		return nil, err
	}
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	var out *api.CopySnapshotResult
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		source, err := tx.RegionalSnapshot(scope.Partition, sourceRegion, value(in.SourceSnapshotId))
		if errors.Is(err, ErrNotFound) {
			source = SnapshotRecord{Key: SnapshotKey{Scope: Scope{Partition: scope.Partition, Region: sourceRegion}, ID: value(in.SourceSnapshotId)}}
		} else if err != nil {
			return err
		} else {
			s.observeSnapshot(ctx, source)
		}
		destination := SnapshotRecord{Key: SnapshotKey{Scope: scope, ID: "*"}}
		conditions := map[string][]string{"ec2:SnapshotID": {"*"}}
		for _, tag := range tags {
			conditions["aws:RequestTag/"+value(tag.Key)] = []string{value(tag.Value)}
			conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], value(tag.Key))
		}
		if err := s.authorize(ctx, "ec2", "CopySnapshot", destination, conditions); err != nil {
			return err
		}
		authority := source
		if source.Key.AccountID != scope.AccountID && source.Key.AccountID != "" {
			authority.Tags, err = tx.SharedTags(SharedTagsKey{Snapshot: source.Key, AccountID: scope.AccountID})
			if err != nil {
				return err
			}
		}
		if err := s.authorize(ctx, "ec2", "CopySnapshot", authority, nil); err != nil {
			return err
		}
		if len(tags) > 0 {
			conditions["ec2:CreateAction"] = []string{"CopySnapshot"}
			if err := s.authorize(ctx, "ec2", "CreateTags", destination, conditions); err != nil {
				return err
			}
		}
		if err := ec2DryRun(in.DryRun); err != nil {
			return err
		}
		if region := value(in.DestinationRegion); region != "" && region != scope.Region {
			return ec2Failure("InvalidParameterValue", "DestinationRegion '"+region+"' does not match the current region ("+scope.Region+")")
		}
		if err := copyURL(value(in.PresignedUrl), sourceRegion, source.Key.ID, scope.Region); err != nil {
			return err
		}
		if in.DestinationOutpostArn != nil || in.DestinationAvailabilityZone != nil {
			// TODO: Comeback integrate snapshot placement with real Outpost and
			// Local Zone resource owners; regional copies never invent placement.
			return ec2Failure("UnsupportedOperation", "Snapshot copies to Outposts and Local Zones are not implemented.")
		}
		visible := false
		if source.Key.AccountID != "" && !source.Deleted {
			visible, err = s.ec2Visible(tx, source)
			if err != nil {
				return err
			}
		}
		keyARN, err := s.copyDestinationKey(ctx, tx, in, visible && source.KMSKeyARN != "")
		if err != nil {
			return err
		}
		counts, err := tx.SnapshotCounts(scope)
		if err != nil {
			return err
		}
		if counts.Copying >= 20 {
			return ec2Failure("ResourceLimitExceeded", "The maximum number of concurrent snapshot copies has been reached.")
		}
		if counts.Total >= 100000 {
			return ec2Failure("SnapshotLimitExceeded", "The maximum number of snapshots has been reached.")
		}
		id, err := tx.NextID(scope)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		destination = SnapshotRecord{
			Key: SnapshotKey{Scope: scope, ID: id}, LineageID: source.LineageID,
			Description: value(in.Description), Created: now, Status: ebsapi.StatusPENDING,
			Sealed: true, CompleteAt: now.Add(CompletionDelay), ReadableAt: now.Add(CompletionDelay + ReadinessDelay),
			KMSKeyARN: keyARN, TokenKey: make([]byte, 32), Tags: make(map[string]string, len(tags)),
			Copy: &SnapshotCopy{Source: source.Key,
				RequestID: awsctx.FromContext(ctx).RequestID, ParentEventID: apievents.EventID(ctx)},
		}
		_, _ = rand.Read(destination.TokenKey)
		for _, tag := range tags {
			destination.Tags[value(tag.Key)] = value(tag.Value)
		}
		if in.CompletionDurationMinutes != nil {
			destination.Copy.CompletionDurationMinutes = int32(*in.CompletionDurationMinutes)
		}
		if !visible {
			destination.StateMessage = "Source snapshot is not found"
		} else if source.Status != ebsapi.StatusCOMPLETED {
			destination.StateMessage = "Source snapshot is not complete"
		}
		var material SnapshotCopyKeys
		if destination.StateMessage == "" {
			destination.VolumeSize = source.VolumeSize
			previous, err := previousCopy(tx, source, destination)
			if err != nil {
				return err
			}
			destination.Copy.Incremental = previous != nil
			if source.KMSKeyARN != "" || destination.KMSKeyARN != "" {
				if s.ec2Keys == nil {
					return errors.New("EC2 snapshot copy encryption is not configured")
				}
				var rejected *awswire.Error
				material, rejected = s.ec2Keys.PrepareCopy(ctx, source, destination, previous)
				if rejected != nil {
					if rejected.StatusCode >= 500 {
						return rejected
					}
					destination.StateMessage = "Given key ID is not accessible"
				} else {
					destination.WrappedKey, destination.KMSKeyARN = material.WrappedKey, material.KMSKeyARN
					destination.Copy.KeySource = material.KeySource
					destination.Copy.SourceGrantToken = material.SourceGrantToken
					destination.Copy.DestinationGrantToken = material.DestinationGrantToken
					destination.Copy.DestinationEncryptGrantToken = material.DestinationEncryptGrantToken
				}
			}
		}
		if destination.StateMessage == "" {
			destination.Copy.WorkAt = now
		}
		if err := tx.PutSnapshot(destination); err != nil {
			return err
		}
		out = &api.CopySnapshotResult{SnapshotId: new(api.String(id)), Tags: tags}
		return nil
	})
	if err == nil {
		s.jobs.Wake()
	}
	return out, err
}

func (s *Service) copyDestinationKey(ctx context.Context, r Reader, in *api.CopySnapshotRequest, sourceEncrypted bool) (string, error) {
	defaults, err := s.encryptionDefault(r)
	if err != nil {
		return "", err
	}
	if !sourceEncrypted && !defaults.Enabled && !(in.Encrypted != nil && bool(*in.Encrypted)) && in.KmsKeyId == nil {
		return "", nil
	}
	if s.ec2Keys == nil {
		return "", errors.New("EC2 snapshot copy encryption is not configured")
	}
	keyID := value(in.KmsKeyId)
	if in.KmsKeyId == nil {
		keyID = defaults.KMSKeyID
		if keyID == "" || keyID == "alias/aws/ebs" {
			var rejected *awswire.Error
			keyID, rejected = s.ec2Keys.EnsureServiceKey(ctx, "ebs")
			if rejected != nil {
				return "", rejected
			}
		}
	}
	metadata, rejected := s.ec2Keys.DescribeKey(ctx, keyID)
	if rejected != nil {
		if rejected.Code == "AccessDeniedException" || rejected.Code == "AccessDenied" {
			return "", failure("AuthFailure", "Not authorized to use key "+keyID+" ", "", 403)
		}
		return "", ec2Failure("InvalidParameterValue", "The specified keyId "+keyID+" is invalid")
	}
	if value(metadata.KeyState) == "Disabled" {
		return "", ec2Failure("InvalidParameterValue", "The specified keyId "+keyID+" is disabled")
	}
	if value(metadata.KeyState) != "Enabled" || value(metadata.KeySpec) != "SYMMETRIC_DEFAULT" || value(metadata.KeyUsage) != "ENCRYPT_DECRYPT" {
		return "", ec2Failure("InvalidParameterValue", "The specified keyId "+keyID+" is invalid")
	}
	return value(metadata.Arn), nil
}

// previousCopy determines incremental eligibility from retained snapshot lineage,
// not payload equality. Deleting the latest destination copy ends its reuse.
func previousCopy(r Reader, source, destination SnapshotRecord) (*SnapshotRecord, error) {
	// Native same-Region shared copies also report incremental; account
	// transfer does not itself require a different block-encryption domain.
	if source.Key.Partition == destination.Key.Partition && source.Key.Region == destination.Key.Region && source.KMSKeyARN == destination.KMSKeyARN {
		return &source, nil
	}
	records, err := r.Snapshots(destination.Key.Scope)
	if err != nil {
		return nil, err
	}
	var latest *SnapshotRecord
	for _, record := range records {
		if record.Copy == nil || record.LineageID != source.LineageID || record.Status != ebsapi.StatusCOMPLETED {
			continue
		}
		if latest == nil || record.Created.After(latest.Created) || record.Created.Equal(latest.Created) && record.Key.ID > latest.Key.ID {
			latest = &record
		}
	}
	if latest == nil || latest.Deleted || latest.KMSKeyARN != destination.KMSKeyARN {
		return nil, nil
	}
	return latest, nil
}
