package codepipeline

import (
	"database/sql"
	"errors"
	api "stackd/internal/awsapi/codepipeline"
	domain "stackd/storage/codepipeline"
	"stackd/storage/sqlite/codepipeline/internal/sqlcgen"
)

func (r reader) InvocationJob(sc domain.Scope, id string) (domain.InvocationJob, bool, error) {
	row, err := r.q.GetInvocationJob(r.ctx, sqlcgen.GetInvocationJobParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, JobID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.InvocationJob{}, false, nil
	}
	if err != nil {
		return domain.InvocationJob{}, false, err
	}
	job, err := r.invocationJob(row)
	return job, err == nil, err
}

func (r reader) InvocationJobs(sc domain.Scope, actionID string) ([]domain.InvocationJob, error) {
	rows, err := r.q.ListInvocationJobs(r.ctx, sqlcgen.ListInvocationJobsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ActionID: actionID})
	if err != nil {
		return nil, err
	}
	jobs := make([]domain.InvocationJob, 0, len(rows))
	for _, row := range rows {
		job, err := r.invocationJob(row)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (r reader) invocationJob(row sqlcgen.CodepipelineInvocationJob) (domain.InvocationJob, error) {
	job := domain.InvocationJob{
		Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region},
		ID:    row.JobID, PipelineName: row.PipelineName, Incarnation: row.Incarnation,
		PipelineExecutionID: row.ExecutionID, ActionExecutionID: row.ActionID,
		StageName: row.StageName, ActionName: row.ActionName, Status: row.Status,
		ContinuationToken: row.ContinuationToken, Sequence: row.Sequence, Generation: row.Generation,
		CreatedAt: instant(row.CreatedAt), ExpiresAt: instant(row.ExpiresAt),
		ResultContinuationToken: row.ResultContinuationToken, ActionExpiresAt: instant(row.ActionExpiresAt),
	}
	if row.ExecutionDetailsPresent != 0 {
		job.ExecutionDetails = &api.ExecutionDetails{
			ExternalExecutionId: nullableString[api.ExecutionId](row.ExecutionExternalID),
			Summary:             nullableString[api.ExecutionSummary](row.ExecutionSummary),
		}
		if row.ExecutionPercent.Valid {
			job.ExecutionDetails.PercentComplete = new(api.Percentage(row.ExecutionPercent.Int64))
		}
	}
	if row.FailureDetailsPresent != 0 {
		job.FailureDetails = &api.FailureDetails{
			ExternalExecutionId: nullableString[api.ExecutionId](row.FailureExternalID),
			Message:             nullableString[api.Message](row.FailureMessage), Type: nullableString[api.FailureType](row.FailureType),
		}
	}
	if row.CurrentRevisionPresent != 0 {
		job.CurrentRevision = &api.CurrentRevision{
			ChangeIdentifier: nullableString[api.RevisionChangeIdentifier](row.RevisionChangeID),
			Revision:         nullableString[api.Revision](row.RevisionID), RevisionSummary: nullableString[api.RevisionSummary](row.RevisionSummary),
		}
		if row.RevisionCreated.Valid {
			job.CurrentRevision.Created = new(instant(row.RevisionCreated.Int64))
		}
	}
	if row.OutputVariablesPresent != 0 {
		job.OutputVariables = api.OutputVariablesMap{}
	}
	variables, err := r.q.ListInvocationJobVariables(r.ctx, sqlcgen.ListInvocationJobVariablesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, JobID: row.JobID})
	if err != nil {
		return domain.InvocationJob{}, err
	}
	for _, variable := range variables {
		job.OutputVariables[api.OutputVariablesKey(variable.Name)] = api.OutputVariablesValue(variable.Value)
	}
	return job, nil
}

func (w writer) PutInvocationJob(job domain.InvocationJob) error {
	row := sqlcgen.PutInvocationJobParams{
		Partition: job.Partition, AccountID: job.AccountID, Region: job.Region, JobID: job.ID,
		PipelineName: job.PipelineName, Incarnation: job.Incarnation, ExecutionID: job.PipelineExecutionID,
		ActionID: job.ActionExecutionID, StageName: job.StageName, ActionName: job.ActionName,
		Status: job.Status, ContinuationToken: job.ContinuationToken, Sequence: job.Sequence, Generation: job.Generation,
		CreatedAt: nanos(job.CreatedAt), ExpiresAt: nanos(job.ExpiresAt), OutputVariablesPresent: flag(job.OutputVariables != nil),
		ExecutionDetailsPresent: flag(job.ExecutionDetails != nil), FailureDetailsPresent: flag(job.FailureDetails != nil),
		CurrentRevisionPresent:  flag(job.CurrentRevision != nil),
		ResultContinuationToken: job.ResultContinuationToken, ActionExpiresAt: nanos(job.ActionExpiresAt),
	}
	if d := job.ExecutionDetails; d != nil {
		row.ExecutionExternalID = sqlString(d.ExternalExecutionId)
		row.ExecutionSummary = sqlString(d.Summary)
		if d.PercentComplete != nil {
			row.ExecutionPercent = sql.NullInt64{Int64: int64(*d.PercentComplete), Valid: true}
		}
	}
	if d := job.FailureDetails; d != nil {
		row.FailureExternalID = sqlString(d.ExternalExecutionId)
		row.FailureMessage = sqlString(d.Message)
		row.FailureType = sqlString(d.Type)
	}
	if d := job.CurrentRevision; d != nil {
		row.RevisionChangeID = sqlString(d.ChangeIdentifier)
		row.RevisionID = sqlString(d.Revision)
		row.RevisionSummary = sqlString(d.RevisionSummary)
		if d.Created != nil {
			row.RevisionCreated = sql.NullInt64{Int64: nanos(*d.Created), Valid: true}
		}
	}
	if err := w.q.PutInvocationJob(w.ctx, row); err != nil {
		return err
	}
	if err := w.q.DeleteInvocationJobVariables(w.ctx, sqlcgen.DeleteInvocationJobVariablesParams{Partition: job.Partition, AccountID: job.AccountID, Region: job.Region, JobID: job.ID}); err != nil {
		return err
	}
	for name, value := range job.OutputVariables {
		if err := w.q.PutInvocationJobVariable(w.ctx, sqlcgen.PutInvocationJobVariableParams{Partition: job.Partition, AccountID: job.AccountID, Region: job.Region, JobID: job.ID, Name: string(name), Value: string(value)}); err != nil {
			return err
		}
	}
	return nil
}

func sqlString[T ~string](value *T) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*value), Valid: true}
}

func nullableString[T ~string](value sql.NullString) *T {
	if !value.Valid {
		return nil
	}
	return new(T(value.String))
}
