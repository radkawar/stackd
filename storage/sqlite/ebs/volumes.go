package ebs

import (
	"database/sql"
	"encoding/json"

	ec2api "stackd/internal/awsapi/ec2"
	kmsapi "stackd/internal/awsapi/kms"
	domain "stackd/storage/ebs"
	"stackd/storage/sqlite/ebs/internal/sqlcgen"
)

func (r reader) volume(v sqlcgen.EbsVolume) (domain.VolumeRecord, error) {
	out := domain.VolumeRecord{
		Key: domain.VolumeKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID},
		Configuration: domain.VolumeConfiguration{
			Size: int32(v.Size), Type: ec2api.VolumeType(v.VolumeType), Iops: int32(v.Iops),
			Throughput: int32(v.Throughput), MultiAttach: v.MultiAttach,
		},
		ZoneName: v.ZoneName, ZoneID: v.ZoneID, SnapshotID: v.SnapshotID, LineageID: v.LineageID,
		Created: v.Created, TransitionAt: timeValue(v.TransitionAt), Status: ec2api.VolumeState(v.Status),
		SnapshotAt:   timeValue(v.SnapshotAt),
		StateMessage: v.StateMessage, AutoEnableIO: v.AutoEnableIo, InitializationRate: int32(v.InitializationRate),
		Encrypted: v.Encrypted, KMSKeyARN: v.KmsKeyArn, WrappedKey: v.WrappedKey,
		NativePath: v.NativePath, ServiceGrantID: kmsapi.GrantIdType(v.ServiceGrantID),
		InfrastructureGrantID: kmsapi.GrantIdType(v.InfrastructureGrantID),
		RequestID:             v.RequestID, ParentEventID: v.ParentEventID,
	}
	var claimErr error
	out.CloudFormationOwner, claimErr = r.cloudFormationClaim(out.Key.Scope, out.Key.ID)
	if claimErr != nil {
		return domain.VolumeRecord{}, claimErr
	}
	if v.CreationSourceID != "" {
		out.Creation = &domain.VolumeCreation{
			Source:           domain.SnapshotKey{Scope: domain.Scope{Partition: v.CreationSourcePartition, AccountID: v.CreationSourceAccountID, Region: v.CreationSourceRegion}, ID: v.CreationSourceID},
			SourceWrappedKey: v.CreationSourceWrappedKey, ReuseSourceCiphertext: v.CreationReuseSourceCiphertext,
			RetireGrant: v.CreationRetireGrant,
		}
	}
	if err := json.Unmarshal([]byte(v.CreationInput), &out.CreationInput); err != nil {
		return domain.VolumeRecord{}, err
	}
	if v.ModificationPresent {
		out.Modification = &domain.VolumeModification{
			Original: domain.VolumeConfiguration{
				Size: int32(v.ModificationOriginalSize), Type: ec2api.VolumeType(v.ModificationOriginalType),
				Iops: int32(v.ModificationOriginalIops), Throughput: int32(v.ModificationOriginalThroughput),
				MultiAttach: v.ModificationOriginalMultiAttach,
			},
			Target: domain.VolumeConfiguration{
				Size: int32(v.ModificationTargetSize), Type: ec2api.VolumeType(v.ModificationTargetType),
				Iops: int32(v.ModificationTargetIops), Throughput: int32(v.ModificationTargetThroughput),
				MultiAttach: v.ModificationTargetMultiAttach,
			},
			Started: timeValue(v.ModificationStarted), OptimizingAt: timeValue(v.ModificationOptimizingAt),
			CompletedAt: timeValue(v.ModificationCompletedAt), State: ec2api.VolumeModificationState(v.ModificationState),
			RequestID: v.ModificationRequestID, ParentEventID: v.ModificationParentEventID,
			StatusMessage: v.ModificationStatusMessage,
		}
	}
	if v.TagsPresent {
		rows, err := r.q.ListVolumeTags(r.ctx, sqlcgen.ListVolumeTagsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, VolumeID: v.ID})
		if err != nil {
			return domain.VolumeRecord{}, err
		}
		out.Tags = make(map[string]string, len(rows))
		for _, row := range rows {
			out.Tags[row.Key] = row.Value
		}
	}
	starts, err := r.q.ListVolumeModificationStarts(r.ctx, sqlcgen.ListVolumeModificationStartsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, VolumeID: v.ID})
	if err != nil {
		return domain.VolumeRecord{}, err
	}
	out.ModificationStarts = starts
	return out, nil
}

func (r reader) Volume(k domain.VolumeKey) (domain.VolumeRecord, error) {
	v, err := r.q.GetVolume(r.ctx, sqlcgen.GetVolumeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID})
	if err != nil {
		return domain.VolumeRecord{}, missing(err)
	}
	return r.volume(v)
}

func (r reader) Volumes(scope domain.Scope) ([]domain.VolumeRecord, error) {
	rows, err := r.q.ListVolumes(r.ctx, sqlcgen.ListVolumesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.VolumeRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.volume(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) VolumeByToken(scope domain.Scope, token string) (domain.VolumeRecord, error) {
	v, err := r.q.GetVolumeByToken(r.ctx, sqlcgen.GetVolumeByTokenParams{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
		ClientToken: sql.NullString{String: token, Valid: true},
	})
	if err != nil {
		return domain.VolumeRecord{}, missing(err)
	}
	return r.volume(v)
}

func (r reader) NextVolumeWork() (domain.VolumeRecord, error) {
	v, err := r.q.NextVolumeWork(r.ctx)
	if err != nil {
		return domain.VolumeRecord{}, missing(err)
	}
	return r.volume(v)
}

func (w writer) NextVolumeID(scope domain.Scope) (string, error) {
	next, err := w.nextSequence(scope)
	if err != nil {
		return "", err
	}
	return domain.VolumeID(scope, next), nil
}

func (w writer) PutVolume(v domain.VolumeRecord) error {
	input, err := json.Marshal(v.CreationInput)
	if err != nil {
		return err
	}
	k, c := v.Key, v.Configuration
	params := sqlcgen.PutVolumeParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.ID,
		Size: int64(c.Size), VolumeType: string(c.Type), Iops: int64(c.Iops),
		Throughput: int64(c.Throughput), MultiAttach: c.MultiAttach,
		ZoneName: v.ZoneName, ZoneID: v.ZoneID, SnapshotID: v.SnapshotID, LineageID: v.LineageID,
		Created: v.Created.UTC(), TransitionAt: nullableTime(v.TransitionAt), Status: string(v.Status),
		SnapshotAt:   nullableTime(v.SnapshotAt),
		StateMessage: v.StateMessage, AutoEnableIo: v.AutoEnableIO, InitializationRate: int64(v.InitializationRate),
		TagsPresent: v.Tags != nil, Encrypted: v.Encrypted, KmsKeyArn: v.KMSKeyARN, WrappedKey: v.WrappedKey,
		NativePath: v.NativePath, ServiceGrantID: string(v.ServiceGrantID),
		InfrastructureGrantID: string(v.InfrastructureGrantID),
		CreationInput:         string(input), ClientToken: nullableString(v.CreationInput.ClientToken),
		RequestID: v.RequestID, ParentEventID: v.ParentEventID, ModificationPresent: v.Modification != nil,
	}
	if creation := v.Creation; creation != nil {
		params.CreationSourcePartition = creation.Source.Partition
		params.CreationSourceAccountID = creation.Source.AccountID
		params.CreationSourceRegion = creation.Source.Region
		params.CreationSourceID = creation.Source.ID
		params.CreationSourceWrappedKey = creation.SourceWrappedKey
		params.CreationReuseSourceCiphertext = creation.ReuseSourceCiphertext
		params.CreationRetireGrant = creation.RetireGrant
	}
	if m := v.Modification; m != nil {
		params.ModificationOriginalSize = int64(m.Original.Size)
		params.ModificationOriginalType = string(m.Original.Type)
		params.ModificationOriginalIops = int64(m.Original.Iops)
		params.ModificationOriginalThroughput = int64(m.Original.Throughput)
		params.ModificationOriginalMultiAttach = m.Original.MultiAttach
		params.ModificationTargetSize = int64(m.Target.Size)
		params.ModificationTargetType = string(m.Target.Type)
		params.ModificationTargetIops = int64(m.Target.Iops)
		params.ModificationTargetThroughput = int64(m.Target.Throughput)
		params.ModificationTargetMultiAttach = m.Target.MultiAttach
		params.ModificationStarted = nullableTime(m.Started)
		params.ModificationOptimizingAt = nullableTime(m.OptimizingAt)
		params.ModificationCompletedAt = nullableTime(m.CompletedAt)
		params.ModificationState = string(m.State)
		params.ModificationRequestID = m.RequestID
		params.ModificationParentEventID = m.ParentEventID
		params.ModificationStatusMessage = m.StatusMessage
	}
	if err := w.q.PutVolume(w.ctx, params); err != nil {
		return err
	}
	if err := w.putCloudFormationClaim(v.Key.Scope, v.Key.ID, v.CloudFormationOwner); err != nil {
		return err
	}
	if err := w.q.DeleteVolumeTags(w.ctx, sqlcgen.DeleteVolumeTagsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, VolumeID: k.ID}); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutVolumeTag(w.ctx, sqlcgen.PutVolumeTagParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, VolumeID: k.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteVolumeModificationStarts(w.ctx, sqlcgen.DeleteVolumeModificationStartsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, VolumeID: k.ID}); err != nil {
		return err
	}
	for i, started := range v.ModificationStarts {
		if err := w.q.PutVolumeModificationStart(w.ctx, sqlcgen.PutVolumeModificationStartParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, VolumeID: k.ID,
			Position: int64(i), Started: started.UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}
