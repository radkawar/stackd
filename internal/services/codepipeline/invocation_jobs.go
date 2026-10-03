package codepipeline

import (
	"cmp"
	"maps"
	"slices"
	api "stackd/internal/awsapi/codepipeline"
	"time"
)

// InvocationJob is one callback-bearing Lambda invocation, not an action attempt.
// Continuations retain the action and its artifact locations but get another job.
// Credentials and Lambda payloads are deliberately never retained here.
type InvocationJob struct {
	Scope
	ID, PipelineName, Incarnation, PipelineExecutionID, ActionExecutionID string
	StageName, ActionName, Status, ContinuationToken                      string
	ResultContinuationToken                                               string
	Sequence, Generation                                                  int64
	CreatedAt, ExpiresAt, ActionExpiresAt                                 time.Time
	ExecutionDetails                                                      *api.ExecutionDetails
	FailureDetails                                                        *api.FailureDetails
	CurrentRevision                                                       *api.CurrentRevision
	OutputVariables                                                       api.OutputVariablesMap
}

func cloneInvocationJob(job InvocationJob) InvocationJob {
	job.OutputVariables = maps.Clone(job.OutputVariables)
	if job.ExecutionDetails != nil {
		d := *job.ExecutionDetails
		d.ExternalExecutionId = copyPtr(d.ExternalExecutionId)
		d.PercentComplete = copyPtr(d.PercentComplete)
		d.Summary = copyPtr(d.Summary)
		job.ExecutionDetails = &d
	}
	if job.FailureDetails != nil {
		d := *job.FailureDetails
		d.ExternalExecutionId = copyPtr(d.ExternalExecutionId)
		d.Message = copyPtr(d.Message)
		d.Type = copyPtr(d.Type)
		job.FailureDetails = &d
	}
	if job.CurrentRevision != nil {
		d := *job.CurrentRevision
		d.ChangeIdentifier = copyPtr(d.ChangeIdentifier)
		d.Created = copyPtr(d.Created)
		d.Revision = copyPtr(d.Revision)
		d.RevisionSummary = copyPtr(d.RevisionSummary)
		job.CurrentRevision = &d
	}
	return job
}

func (r memoryReader) InvocationJob(sc Scope, id string) (InvocationJob, bool, error) {
	job, found := r.s.invocationJobs[executionKey{sc, id}]
	return cloneInvocationJob(job), found, nil
}

func (r memoryReader) InvocationJobs(sc Scope, actionID string) ([]InvocationJob, error) {
	jobs := []InvocationJob{}
	for _, job := range r.s.invocationJobs {
		if job.Scope == sc && job.ActionExecutionID == actionID {
			jobs = append(jobs, cloneInvocationJob(job))
		}
	}
	slices.SortFunc(jobs, func(a, b InvocationJob) int { return cmp.Compare(a.Sequence, b.Sequence) })
	return jobs, nil
}

func (w memoryWriter) PutInvocationJob(job InvocationJob) error {
	w.s.invocationJobs[executionKey{job.Scope, job.ID}] = cloneInvocationJob(job)
	return nil
}

func latestInvocationJob(r Reader, sc Scope, actionID string) (*InvocationJob, error) {
	jobs, err := r.InvocationJobs(sc, actionID)
	if err != nil || len(jobs) == 0 {
		return nil, err
	}
	return &jobs[len(jobs)-1], nil
}

func (s *Service) admitInvocationJob(tx Transaction, e Execution, a ActionExecution, decl api.ActionDeclaration) error {
	id, err := newID()
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	deadline := a.StartedAt.Add(24 * time.Hour)
	if decl.TimeoutInMinutes != nil {
		deadline = a.StartedAt.Add(time.Duration(*decl.TimeoutInMinutes) * time.Minute)
	}
	return tx.PutInvocationJob(InvocationJob{
		Scope: e.Scope, ID: id, PipelineName: e.PipelineName, Incarnation: e.Incarnation,
		PipelineExecutionID: e.ID, ActionExecutionID: a.ID, StageName: a.StageName, ActionName: a.ActionName,
		Status: "Ready", Sequence: 1, Generation: 1, CreatedAt: now,
		ExpiresAt: invocationExpiry(now, deadline), ActionExpiresAt: deadline,
	})
}

func invocationExpiry(now, deadline time.Time) time.Time {
	expires := now.Add(20 * time.Minute)
	if deadline.Before(expires) {
		return deadline
	}
	return expires
}
