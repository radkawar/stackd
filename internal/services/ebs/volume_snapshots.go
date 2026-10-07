package ebs

import (
	"context"
	"crypto/rand"
	"slices"
	"time"

	"stackd/internal/apievents"
	ebsapi "stackd/internal/awsapi/ebs"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
)

// VolumeSnapshotInterval is local admission timing: native fixtures establish an
// immediate rejection and a successful repeat after one minute, not a finer SLA.
const VolumeSnapshotInterval = time.Minute

func (s *Service) CreateSnapshot(ctx context.Context, in *api.CreateSnapshotRequest) (*api.Snapshot, error) {
	if err := s.advance(ctx); err != nil {
		return nil, err
	}
	tags, err := ec2.CreationTags(in.TagSpecifications, "snapshot")
	if err != nil {
		return nil, err
	}
	description := value(in.Description)
	for _, c := range description {
		if c > 127 {
			return nil, ec2Failure("InvalidParameterValue", "Value ("+description+") for parameter description is invalid. Character sets beyond ASCII are not supported.")
		}
	}
	s.nativeWorkMu.Lock()
	defer s.nativeWorkMu.Unlock()
	var snapshot SnapshotRecord
	var out *api.Snapshot
	err = s.repository.Update(ctx, func(tx Transaction) error {
		source, err := s.volumeControl(tx, "CreateSnapshot", in.VolumeId, nil)
		if err != nil {
			return err
		}
		if err := s.authorizeVolumeSnapshot(tx.Context(), source, tags, "CreateSnapshot"); err != nil {
			return err
		}
		if err := ec2DryRun(in.DryRun); err != nil {
			return err
		}
		if err := deletionSnapshotFence(tx, source); err != nil {
			return err
		}
		if in.OutpostArn != nil || in.Location != nil && *in.Location != "regional" {
			return ec2Failure("UnsupportedOperation", "Snapshot placement outside the Region is not implemented.")
		}
		if !source.SnapshotAt.IsZero() && s.clock.Now().Before(source.SnapshotAt.Add(VolumeSnapshotInterval)) {
			return ec2Failure("SnapshotCreationPerVolumeRateExceeded", "The maximum per volume CreateSnapshot request rate has been exceeded. Use an increasing or variable sleep interval between requests.")
		}
		snapshot, err = s.admitVolumeSnapshot(tx, source, tags, description, true)
		if err != nil {
			return err
		}
		if err := admitDeletionSnapshotOwner(tx, &snapshot); err != nil {
			return err
		}
		if tags == nil {
			tags = api.TagList{}
		}
		out = &api.Snapshot{
			SnapshotId: new(api.String(snapshot.Key.ID)), VolumeId: new(api.String(source.Key.ID)), VolumeSize: new(api.Integer(source.Configuration.Size)),
			State: new(api.SnapshotStatePending), StartTime: new(snapshot.Created), OwnerId: new(api.String(source.Key.AccountID)),
			Description: new(api.String(description)), Progress: new(api.String("")), Encrypted: new(api.Boolean(source.Encrypted)), Tags: tags,
		}
		return ec2.RecordExternalSuccess(tx.Context(), out)
	})
	if err != nil {
		return nil, err
	}
	// Admission fixes the capture edge. Never defer choosing the disk bytes to
	// an arbitrary scheduler invocation. Errors after this point belong to the
	// accepted pending snapshot and are published by the shared lifecycle.
	if snapshot.Volume.NativeBackupPath != "" {
		_ = s.captureNativeSnapshots(ctx, []SnapshotRecord{snapshot})
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) authorizeVolumeSnapshot(ctx context.Context, source VolumeRecord, tags api.TagList, action string) error {
	destination := SnapshotRecord{Key: SnapshotKey{Scope: source.Key.Scope, ID: "*"}}
	conditions := volumeRequestConditions(tags)
	conditions["ec2:ParentVolume"] = []string{volumeARN(source.Key)}
	if err := s.authorize(ctx, "ec2", action, destination, conditions); err != nil {
		return err
	}
	if len(tags) > 0 {
		conditions["ec2:CreateAction"] = []string{action}
		return s.authorize(ctx, "ec2", "CreateTags", destination, conditions)
	}
	return nil
}

func (s *Service) admitVolumeSnapshot(tx Transaction, source VolumeRecord, tags api.TagList, description string, captureNow bool) (SnapshotRecord, error) {
	var zero SnapshotRecord
	if source.Creation != nil || source.Status != api.VolumeStateAvailable && source.Status != api.VolumeStateIn_use {
		return zero, ec2Failure("IncorrectState", "Volume '"+source.Key.ID+"' is not in the 'available' or 'in-use' state.")
	}
	if source.NativePath != "" && s.nativeDisks == nil {
		return zero, ec2Failure("UnsupportedOperation", "Native disk snapshots are not configured.")
	}
	counts, err := tx.SnapshotCounts(source.Key.Scope)
	if err != nil {
		return zero, err
	}
	if counts.Total >= 100000 {
		return zero, ec2Failure("SnapshotLimitExceeded", "The maximum number of snapshots has been reached.")
	}
	id, err := tx.NextID(source.Key.Scope)
	if err != nil {
		return zero, err
	}
	now := s.clock.Now()
	destination := SnapshotRecord{
		Key: SnapshotKey{Scope: source.Key.Scope, ID: id}, LineageID: source.LineageID,
		VolumeSize: int64(source.Configuration.Size), Description: description,
		Created: now, Status: ebsapi.StatusPENDING,
		KMSKeyARN: source.KMSKeyARN, WrappedKey: slices.Clone(source.WrappedKey), TokenKey: make([]byte, 32),
		Tags:   make(map[string]string, len(tags)),
		Volume: &SnapshotVolume{Source: source.Key, RequestID: awsctx.FromContext(tx.Context()).RequestID, ParentEventID: apievents.EventID(tx.Context())},
	}
	if _, err := rand.Read(destination.TokenKey); err != nil {
		return zero, err
	}
	for _, tag := range tags {
		destination.Tags[value(tag.Key)] = value(tag.Value)
	}
	if source.NativePath != "" {
		destination.Volume.NativeBackupPath = source.NativePath + "." + id + ".snapshot.qcow2"
		if captureNow {
			destination.Volume.NativeWorkAt = now
		}
	} else {
		destination.Volume.BlocksWorkAt = now
	}
	if err := tx.PutSnapshot(destination); err != nil {
		return zero, err
	}
	source.SnapshotAt = now
	if err := tx.PutVolume(source); err != nil {
		return zero, err
	}
	return destination, nil
}
