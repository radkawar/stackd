package codepipeline

import (
	"maps"
	"slices"
	api "stackd/internal/awsapi/codepipeline"
)

func registerInvocationJobs(s *Service) {
	register(s, "PutJobSuccessResult", s.putJobSuccess)
	register(s, "PutJobFailureResult", s.putJobFailure)
}

// Callbacks acknowledge a retained job only. The scheduler consumes its result
// through the provider adapter and the existing action-completion/event path.
// Lambda reports reserved artifact locators; downstream owners read real objects.
func (s *Service) callbackJob(tx Transaction, operation, id string) (InvocationJob, Execution, error) {
	if err := s.authorize(tx.Context(), operation, "*", nil); err != nil {
		return InvocationJob{}, Execution{}, err
	}
	missing := failure("JobNotFoundException", "Job with id '"+id+"' does not exist")
	job, found, err := tx.InvocationJob(scopeFor(tx.Context()), id)
	if err != nil {
		return job, Execution{}, err
	}
	if !found {
		return job, Execution{}, missing
	}
	if job.Status != "Ready" && job.Status != "Running" {
		// Completed job replay is retained even after its pipeline is deleted.
		// It has no execution effect and cannot target a replacement pipeline.
		return job, Execution{}, nil
	}
	v, err := findPipeline(tx, job.Scope, job.PipelineName)
	if err != nil || v.Incarnation != job.Incarnation {
		return job, Execution{}, missing
	}
	e, err := findExecution(tx, v, job.PipelineExecutionID)
	if err != nil {
		return job, e, err
	}
	if e.UpdatedDefinition || !s.clock.Now().Before(job.ExpiresAt) {
		return job, e, missing
	}
	i := slices.IndexFunc(e.Actions, func(a ActionExecution) bool { return a.ID == job.ActionExecutionID })
	if i < 0 {
		return job, e, missing
	}
	a := e.Actions[i]
	latest := latestAction(e, a.StageIndex, a.ActionIndex)
	if latest == nil || latest.ID != a.ID {
		return job, e, missing
	}
	current, err := latestInvocationJob(tx, job.Scope, a.ID)
	if err != nil {
		return job, e, err
	}
	if current == nil || current.ID != job.ID {
		return job, e, missing
	}
	return job, e, nil
}

func (s *Service) putJobSuccess(tx Transaction, in *api.PutJobSuccessResultInput) (*api.PutJobSuccessResultOutput, error) {
	job, e, err := s.callbackJob(tx, "PutJobSuccessResult", text(in.JobId))
	if err != nil {
		return nil, err
	}
	if text(in.ContinuationToken) != "" && len(in.OutputVariables) != 0 {
		return nil, failure("ValidationException", "A job can not contain both a continuation token and output variables.")
	}
	size := 0
	for key, value := range in.OutputVariables {
		size += len(key) + len(value)
		if size > 122880 {
			return nil, failure("OutputVariablesSizeExceededException", "Output variables exceed the maximum size")
		}
	}
	if job.Status != "Ready" && job.Status != "Running" {
		if (job.Status == "Succeeded" || job.Status == "Continued") &&
			job.ResultContinuationToken == text(in.ContinuationToken) &&
			equalExecutionDetails(job.ExecutionDetails, in.ExecutionDetails) &&
			equalCurrentRevision(job.CurrentRevision, in.CurrentRevision) &&
			maps.Equal(job.OutputVariables, in.OutputVariables) {
			return &api.PutJobSuccessResultOutput{}, nil
		}
		return nil, invocationResultConflict(job, job.Status == "Succeeded" || job.Status == "Continued")
	}
	job.ExecutionDetails = in.ExecutionDetails
	job.CurrentRevision = in.CurrentRevision
	job.OutputVariables = in.OutputVariables
	job.ResultContinuationToken = text(in.ContinuationToken)
	job.Generation++
	job.Status = "Succeeded"
	if text(in.ContinuationToken) != "" {
		job.Status = "Continued"
	}
	if job.Status == "Continued" && invocationActionActive(e, job) {
		id, err := newID()
		if err != nil {
			return nil, err
		}
		next := InvocationJob{
			Scope: job.Scope, ID: id, PipelineName: job.PipelineName, Incarnation: job.Incarnation,
			PipelineExecutionID: job.PipelineExecutionID, ActionExecutionID: job.ActionExecutionID,
			StageName: job.StageName, ActionName: job.ActionName, Status: "Ready",
			ContinuationToken: text(in.ContinuationToken), Sequence: job.Sequence + 1, Generation: 1,
			CreatedAt: s.clock.Now().UTC(), ExpiresAt: invocationExpiry(s.clock.Now().UTC(), job.ActionExpiresAt),
			ActionExpiresAt: job.ActionExpiresAt,
		}
		if err := tx.PutInvocationJob(next); err != nil {
			return nil, err
		}
	}
	if err := s.saveInvocationCallback(tx, job, e); err != nil {
		return nil, err
	}
	return &api.PutJobSuccessResultOutput{}, nil
}

func (s *Service) putJobFailure(tx Transaction, in *api.PutJobFailureResultInput) (*api.PutJobFailureResultOutput, error) {
	job, e, err := s.callbackJob(tx, "PutJobFailureResult", text(in.JobId))
	if err != nil {
		return nil, err
	}
	if in.FailureDetails == nil {
		return nil, failure("ValidationException", "Failure details are required")
	}
	if job.Status != "Ready" && job.Status != "Running" {
		if job.Status == "Failed" && equalFailureDetails(job.FailureDetails, in.FailureDetails) {
			return &api.PutJobFailureResultOutput{}, nil
		}
		return nil, invocationResultConflict(job, job.Status == "Failed")
	}
	job.FailureDetails = in.FailureDetails
	job.Status = "Failed"
	job.Generation++
	if err := s.saveInvocationCallback(tx, job, e); err != nil {
		return nil, err
	}
	return &api.PutJobFailureResultOutput{}, nil
}

func (s *Service) saveInvocationCallback(tx Transaction, job InvocationJob, e Execution) error {
	if err := tx.PutInvocationJob(job); err != nil {
		return err
	}
	if !invocationActionActive(e, job) {
		// Native accepts a callback after abandonment. Retain its replay
		// identity, but never revive the fenced action or schedule more work.
		return nil
	}
	e.Due = s.clock.Now().UTC()
	e.UpdatedAt = e.Due
	e.Generation++
	return tx.PutExecution(e)
}

func invocationActionActive(e Execution, job InvocationJob) bool {
	if terminal(e.Status) || e.UpdatedDefinition {
		return false
	}
	for _, a := range e.Actions {
		if a.ID == job.ActionExecutionID {
			latest := latestAction(e, a.StageIndex, a.ActionIndex)
			return a.Status == "InProgress" && latest != nil && latest.ID == a.ID
		}
	}
	return false
}
