package codebuild

import (
	api "stackd/internal/awsapi/codebuild"
	domain "stackd/storage/codebuild"
	"stackd/storage/sqlite/codebuild/internal/sqlcgen"
)

func (r reader) Build(k domain.BuildKey) (domain.BuildRecord, error) {
	row, err := r.q.GetBuild(r.ctx, sqlcgen.GetBuildParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
	if err != nil {
		return domain.BuildRecord{}, missing(err)
	}
	return r.build(row)
}

func (r reader) Builds(k domain.Scope) ([]domain.BuildRecord, error) {
	rows, err := r.q.ListBuilds(r.ctx, sqlcgen.ListBuildsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	return r.builds(rows)
}

func (r reader) ActiveBuilds() ([]domain.BuildRecord, error) {
	rows, err := r.q.ListActiveBuilds(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.builds(rows)
}

func (r reader) builds(rows []sqlcgen.CodebuildBuild) ([]domain.BuildRecord, error) {
	out := make([]domain.BuildRecord, len(rows))
	for i, row := range rows {
		var err error
		out[i], err = r.build(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) build(row sqlcgen.CodebuildBuild) (domain.BuildRecord, error) {
	out := domain.BuildRecord{
		Key:             domain.BuildKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID},
		AcceptedEventID: row.AcceptedEventID, IdempotencyToken: row.IdempotencyToken, RequestHash: row.RequestHash,
		Deadline: deadlineTime(row.Deadline), QueuedDeadline: deadlineTime(row.QueuedDeadline), StopRequested: row.StopRequested,
		DeleteRequested: row.DeleteRequested, CleanupPending: row.CleanupPending, CredentialToken: row.CredentialToken,
		LogOffset: row.LogOffset, Failure: row.Failure, FleetARN: row.FleetArn,
		PipelineActionID: row.PipelineActionID, RetrySourceID: row.RetrySourceID,
		Data: api.Build{
			Arn: stringPointer[api.NonEmptyString](row.Arn), Id: stringPointer[api.NonEmptyString](row.BuildID),
			BuildBatchArn: stringPointer[api.String](row.BuildBatchArn), BuildComplete: boolPointer[api.Boolean](row.BuildComplete),
			BuildNumber: integerPointer[api.WrapperLong](row.BuildNumber), BuildStatus: stringPointer[api.StatusType](row.BuildStatus),
			CurrentPhase: stringPointer[api.String](row.CurrentPhase), EncryptionKey: stringPointer[api.NonEmptyString](row.EncryptionKey),
			EndTime: timePointer(row.EndTime), Initiator: stringPointer[api.String](row.Initiator), ProjectName: stringPointer[api.NonEmptyString](row.ProjectName),
			QueuedTimeoutInMinutes: integerPointer[api.WrapperInt](row.QueuedTimeoutInMinutes), ResolvedSourceVersion: stringPointer[api.NonEmptyString](row.ResolvedSourceVersion),
			ServiceRole: stringPointer[api.NonEmptyString](row.ServiceRole), SourceVersion: stringPointer[api.NonEmptyString](row.SourceVersion),
			StartTime: timePointer(row.StartTime), TimeoutInMinutes: integerPointer[api.WrapperInt](row.TimeoutInMinutes),
		},
	}
	if err := unmarshalFields(
		jsonReadField{row.ArtifactsConfig, &out.Artifacts}, jsonReadField{row.LogsConfig, &out.Logs},
		jsonReadField{row.SecondaryArtifactsConfig, &out.SecondaryArtifacts},
		jsonReadField{row.Artifacts, &out.Data.Artifacts}, jsonReadField{row.AutoRetryConfig, &out.Data.AutoRetryConfig},
		jsonReadField{row.Cache, &out.Data.Cache}, jsonReadField{row.DebugSession, &out.Data.DebugSession},
		jsonReadField{row.Environment, &out.Data.Environment}, jsonReadField{row.FileSystemLocations, &out.Data.FileSystemLocations},
		jsonReadField{row.Logs, &out.Data.Logs}, jsonReadField{row.NetworkInterface, &out.Data.NetworkInterface},
		jsonReadField{row.SecondaryArtifacts, &out.Data.SecondaryArtifacts}, jsonReadField{row.SecondarySources, &out.Data.SecondarySources},
		jsonReadField{row.Source, &out.Data.Source}, jsonReadField{row.VpcConfig, &out.Data.VpcConfig},
	); err != nil {
		return domain.BuildRecord{}, err
	}
	if err := r.buildChildren(&out, row); err != nil {
		return domain.BuildRecord{}, err
	}
	if err := r.pipelineArtifacts(&out); err != nil {
		return domain.BuildRecord{}, err
	}
	return out, nil
}

func (w writer) PutBuild(v domain.BuildRecord) error {
	k, d := v.Key, v.Data
	row := sqlcgen.PutBuildParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID,
		AcceptedEventID: v.AcceptedEventID, IdempotencyToken: v.IdempotencyToken, RequestHash: v.RequestHash,
		Deadline: deadlineValue(v.Deadline), QueuedDeadline: deadlineValue(v.QueuedDeadline), StopRequested: v.StopRequested,
		DeleteRequested: v.DeleteRequested, CleanupPending: v.CleanupPending, CredentialToken: v.CredentialToken,
		LogOffset: v.LogOffset, Failure: v.Failure, FleetArn: v.FleetARN,
		PipelineActionID: v.PipelineActionID, RetrySourceID: v.RetrySourceID,
		Arn: nullableString(d.Arn), BuildID: nullableString(d.Id), BuildBatchArn: nullableString(d.BuildBatchArn),
		BuildComplete: nullableBool(d.BuildComplete), BuildNumber: nullableInteger(d.BuildNumber), BuildStatus: nullableString(d.BuildStatus),
		CurrentPhase: nullableString(d.CurrentPhase), EncryptionKey: nullableString(d.EncryptionKey), EndTime: nullableTime(d.EndTime),
		Initiator: nullableString(d.Initiator), ProjectName: nullableString(d.ProjectName), QueuedTimeoutInMinutes: nullableInteger(d.QueuedTimeoutInMinutes),
		ResolvedSourceVersion: nullableString(d.ResolvedSourceVersion), ServiceRole: nullableString(d.ServiceRole), SourceVersion: nullableString(d.SourceVersion),
		StartTime: nullableTime(d.StartTime), TimeoutInMinutes: nullableInteger(d.TimeoutInMinutes),
		EnvironmentVariablesPresent:         d.Environment != nil && d.Environment.EnvironmentVariables != nil,
		ExportedEnvironmentVariablesPresent: d.ExportedEnvironmentVariables != nil, PhasesPresent: d.Phases != nil,
		ReportArnsPresent: d.ReportArns != nil, SecondarySourceVersionsPresent: d.SecondarySourceVersions != nil,
	}
	if err := marshalFields(
		jsonWriteField{&row.ArtifactsConfig, v.Artifacts}, jsonWriteField{&row.LogsConfig, v.Logs},
		jsonWriteField{&row.SecondaryArtifactsConfig, v.SecondaryArtifacts},
		jsonWriteField{&row.Artifacts, d.Artifacts}, jsonWriteField{&row.AutoRetryConfig, d.AutoRetryConfig},
		jsonWriteField{&row.Cache, d.Cache}, jsonWriteField{&row.DebugSession, d.DebugSession},
		jsonWriteField{&row.Environment, environmentConfig(d.Environment)}, jsonWriteField{&row.FileSystemLocations, d.FileSystemLocations},
		jsonWriteField{&row.Logs, d.Logs}, jsonWriteField{&row.NetworkInterface, d.NetworkInterface},
		jsonWriteField{&row.SecondaryArtifacts, d.SecondaryArtifacts}, jsonWriteField{&row.SecondarySources, d.SecondarySources},
		jsonWriteField{&row.Source, d.Source}, jsonWriteField{&row.VpcConfig, d.VpcConfig},
	); err != nil {
		return err
	}
	if err := w.q.PutBuild(w.ctx, row); err != nil {
		return err
	}
	if err := w.putPipelineArtifacts(v); err != nil {
		return err
	}
	return w.putBuildChildren(v)
}

func (w writer) DeleteBuild(k domain.BuildKey) error {
	return w.q.DeleteBuild(w.ctx, sqlcgen.DeleteBuildParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ResourceID: k.ID})
}
