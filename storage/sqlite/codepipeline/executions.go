package codepipeline

import (
	api "stackd/internal/awsapi/codepipeline"
	domain "stackd/storage/codepipeline"
	"stackd/storage/sqlite/codepipeline/internal/sqlcgen"
)

func (r reader) Executions(sc domain.Scope, incarnation string) ([]domain.Execution, error) {
	rows, err := r.q.ListExecutions(r.ctx, sqlcgen.ListExecutionsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Incarnation: incarnation})
	if err != nil {
		return nil, err
	}
	return r.executions(rows)
}
func (r reader) PendingExecutions() ([]domain.Execution, error) {
	rows, err := r.q.PendingExecutions(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.executions(rows)
}
func (r reader) executions(rows []sqlcgen.CodepipelineExecution) ([]domain.Execution, error) {
	out := make([]domain.Execution, 0, len(rows))
	for _, row := range rows {
		e := domain.Execution{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, PipelineName: row.PipelineName, Incarnation: row.Incarnation, ID: row.ExecutionID, ClientToken: row.ClientToken, Version: int32(row.Version), Mode: row.Mode, Status: row.Status, Summary: row.Summary, TriggerType: row.TriggerType, TriggerDetail: row.TriggerDetail, StopReason: row.StopReason, StageIndex: int32(row.StageIndex), StageEntered: row.StageEntered != 0, UpdatedDefinition: row.UpdatedDefinition != 0, StartedAt: instant(row.StartedAt), UpdatedAt: instant(row.UpdatedAt), Due: instant(row.Due), Generation: row.Generation, Sequence: row.Sequence}
		e.ParentEventID = row.ParentEventID
		e.Attempt = int32(row.Attempt)
		e.StageStatus = row.StageStatus
		e.StageStartedAt = instant(row.StageStartedAt)
		e.LastRetryAt = instant(row.LastRetryAt)
		e.StageLastRetryAt = instant(row.StageLastRetryAt)
		e.RollbackTargetID = row.RollbackTargetID
		e.RollbackStageIndex = int32(row.RollbackStageIndex)
		variables, err := r.q.ListExecutionVariables(r.ctx, e.ID)
		if err != nil {
			return nil, err
		}
		for _, variable := range variables {
			e.Variables = append(e.Variables, api.ResolvedPipelineVariable{Name: new(api.String(variable.Name)), ResolvedValue: new(api.String(variable.ResolvedValue))})
		}
		overrides, err := r.q.ListOverrides(r.ctx, e.ID)
		if err != nil {
			return nil, err
		}
		for _, o := range overrides {
			e.SourceOverrides = append(e.SourceOverrides, api.SourceRevisionOverride{ActionName: new(api.ActionName(o.ActionName)), RevisionType: new(api.SourceRevisionType(o.RevisionType)), RevisionValue: new(api.Revision(o.RevisionValue))})
		}
		revisions, err := r.q.ListRevisions(r.ctx, e.ID)
		if err != nil {
			return nil, err
		}
		for _, v := range revisions {
			e.Revisions = append(e.Revisions, domain.SourceRevision{ActionName: v.ActionName, ArtifactName: v.ArtifactName, RevisionID: v.RevisionID, ChangeID: v.ChangeID, Summary: v.Summary, URL: v.Url, CreatedAt: instant(v.CreatedAt)})
		}
		actions, err := r.q.ListActionExecutions(r.ctx, e.ID)
		if err != nil {
			return nil, err
		}
		for _, v := range actions {
			a := domain.ActionExecution{ID: v.ActionID, StageName: v.StageName, ActionName: v.ActionName, Status: v.Status, StageIndex: int32(v.StageIndex), ActionIndex: int32(v.ActionIndex), Attempt: int32(v.Attempt), StartedAt: instant(v.StartedAt), UpdatedAt: instant(v.UpdatedAt), ExternalExecutionID: v.ExternalID, ExternalExecutionURL: v.ExternalUrl, Summary: v.Summary, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage, ApprovalToken: v.ApprovalToken, ResolvedConfiguration: api.ActionConfigurationMap{}, OutputVariables: api.OutputVariablesMap{}}
			a.UpdatedBy = v.UpdatedBy
			a.ApprovalNotificationID = v.ApprovalNotificationID
			artifacts, err := r.q.ListArtifacts(r.ctx, a.ID)
			if err != nil {
				return nil, err
			}
			for _, v := range artifacts {
				artifact := domain.Artifact{Name: v.Name, Bucket: v.Bucket, Key: v.ObjectKey, VersionID: v.VersionID, ETag: v.Etag, RevisionID: v.RevisionID, ActionExecutionID: v.ProducerID}
				if v.Direction == "input" {
					a.InputArtifacts = append(a.InputArtifacts, artifact)
				} else {
					a.OutputArtifacts = append(a.OutputArtifacts, artifact)
				}
			}
			values, err := r.q.ListActionValues(r.ctx, a.ID)
			if err != nil {
				return nil, err
			}
			for _, v := range values {
				if v.ValueKind == "configuration" {
					a.ResolvedConfiguration[api.ActionConfigurationKey(v.ValueKey)] = api.ActionConfigurationValue(v.ValueText)
				} else {
					a.OutputVariables[api.OutputVariablesKey(v.ValueKey)] = api.OutputVariablesValue(v.ValueText)
				}
			}
			e.Actions = append(e.Actions, a)
		}
		out = append(out, e)
	}
	return out, nil
}
func (w writer) PutExecution(e domain.Execution) error {
	row := sqlcgen.PutExecutionsParams{
		ExecutionID: e.ID, Partition: e.Partition, AccountID: e.AccountID, Region: e.Region,
		PipelineName: e.PipelineName, Incarnation: e.Incarnation, Version: int64(e.Version),
		ClientToken: e.ClientToken, Mode: e.Mode, Status: e.Status,
		Summary: e.Summary, TriggerType: e.TriggerType, TriggerDetail: e.TriggerDetail, StopReason: e.StopReason,
		StageIndex: int64(e.StageIndex), StageEntered: flag(e.StageEntered), UpdatedDefinition: flag(e.UpdatedDefinition),
		StartedAt: nanos(e.StartedAt), UpdatedAt: nanos(e.UpdatedAt), Due: nanos(e.Due),
		Generation: e.Generation, Sequence: e.Sequence, ParentEventID: e.ParentEventID,
		Attempt: int64(e.Attempt), StageStatus: e.StageStatus,
		StageStartedAt: nanos(e.StageStartedAt),
		LastRetryAt:    nanos(e.LastRetryAt), StageLastRetryAt: nanos(e.StageLastRetryAt),
		RollbackTargetID: e.RollbackTargetID, RollbackStageIndex: int64(e.RollbackStageIndex),
	}
	if err := w.q.PutExecutions(w.ctx, row); err != nil {
		return err
	}
	if err := w.q.DeleteExecutionVariables(w.ctx, e.ID); err != nil {
		return err
	}
	for i, variable := range e.Variables {
		if err := w.q.PutExecutionVariables(w.ctx, sqlcgen.PutExecutionVariablesParams{ExecutionID: e.ID, Position: int64(i), Name: text(variable.Name), ResolvedValue: text(variable.ResolvedValue)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteOverrides(w.ctx, e.ID); err != nil {
		return err
	}
	for i, o := range e.SourceOverrides {
		if err := w.q.PutOverrides(w.ctx, sqlcgen.PutOverridesParams{ExecutionID: e.ID, Position: int64(i), ActionName: text(o.ActionName), RevisionType: text(o.RevisionType), RevisionValue: text(o.RevisionValue)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteRevisions(w.ctx, e.ID); err != nil {
		return err
	}
	for i, r := range e.Revisions {
		if err := w.q.PutRevisions(w.ctx, sqlcgen.PutRevisionsParams{ExecutionID: e.ID, Position: int64(i), ActionName: r.ActionName, ArtifactName: r.ArtifactName, RevisionID: r.RevisionID, ChangeID: r.ChangeID, Summary: r.Summary, Url: r.URL, CreatedAt: nanos(r.CreatedAt)}); err != nil {
			return err
		}
	}
	old, err := w.q.ListActionExecutions(w.ctx, e.ID)
	if err != nil {
		return err
	}
	for _, a := range old {
		if err := w.q.DeleteArtifacts(w.ctx, a.ActionID); err != nil {
			return err
		}
		if err := w.q.DeleteActionValues(w.ctx, a.ActionID); err != nil {
			return err
		}
	}
	if err := w.q.DeleteActionExecutions(w.ctx, e.ID); err != nil {
		return err
	}
	for i, a := range e.Actions {
		row := sqlcgen.PutActionExecutionsParams{
			ActionID: a.ID, ExecutionID: e.ID, Position: int64(i),
			StageName: a.StageName, ActionName: a.ActionName, Status: a.Status,
			StageIndex: int64(a.StageIndex), ActionIndex: int64(a.ActionIndex), Attempt: int64(a.Attempt),
			StartedAt: nanos(a.StartedAt), UpdatedAt: nanos(a.UpdatedAt), UpdatedBy: a.UpdatedBy,
			ExternalID: a.ExternalExecutionID, ExternalUrl: a.ExternalExecutionURL,
			Summary: a.Summary, ErrorCode: a.ErrorCode, ErrorMessage: a.ErrorMessage, ApprovalToken: a.ApprovalToken,
			ApprovalNotificationID: a.ApprovalNotificationID,
		}
		if err := w.q.PutActionExecutions(w.ctx, row); err != nil {
			return err
		}
		for i, artifact := range a.InputArtifacts {
			if err := w.putArtifact(a.ID, "input", i, artifact); err != nil {
				return err
			}
		}
		for i, artifact := range a.OutputArtifacts {
			if err := w.putArtifact(a.ID, "output", i, artifact); err != nil {
				return err
			}
		}
		for k, v := range a.ResolvedConfiguration {
			if err := w.q.PutActionValues(w.ctx, sqlcgen.PutActionValuesParams{ActionID: a.ID, ValueKind: "configuration", ValueKey: string(k), ValueText: string(v)}); err != nil {
				return err
			}
		}
		for k, v := range a.OutputVariables {
			if err := w.q.PutActionValues(w.ctx, sqlcgen.PutActionValuesParams{ActionID: a.ID, ValueKind: "output", ValueKey: string(k), ValueText: string(v)}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) putArtifact(action, direction string, position int, a domain.Artifact) error {
	return w.q.PutArtifacts(w.ctx, sqlcgen.PutArtifactsParams{ActionID: action, Direction: direction, Position: int64(position), Name: a.Name, Bucket: a.Bucket, ObjectKey: a.Key, VersionID: a.VersionID, Etag: a.ETag, RevisionID: a.RevisionID, ProducerID: a.ActionExecutionID})
}
