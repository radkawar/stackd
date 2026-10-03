package codepipeline

import (
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awswire"
)

func invocationResultConflict(job InvocationJob, sameStatus bool) *awswire.Error {
	if sameStatus {
		return failure("InvalidJobStateException", "The status of job with id "+job.ID+" is already set to the desired value. It cannot be updated with the same status, but different result or output variables.")
	}
	return failure("InvalidJobStateException", "Job with id "+job.ID+" has already terminated")
}

func equalJobField[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func equalExecutionDetails(a, b *api.ExecutionDetails) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return equalJobField(a.ExternalExecutionId, b.ExternalExecutionId) &&
		equalJobField(a.PercentComplete, b.PercentComplete) && equalJobField(a.Summary, b.Summary)
}

func equalFailureDetails(a, b *api.FailureDetails) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return equalJobField(a.ExternalExecutionId, b.ExternalExecutionId) &&
		equalJobField(a.Type, b.Type) && equalJobField(a.Message, b.Message)
}

func equalCurrentRevision(a, b *api.CurrentRevision) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	createdEqual := a.Created == nil && b.Created == nil
	if a.Created != nil && b.Created != nil {
		createdEqual = a.Created.Equal(*b.Created)
	}
	return createdEqual && equalJobField(a.ChangeIdentifier, b.ChangeIdentifier) &&
		equalJobField(a.Revision, b.Revision) && equalJobField(a.RevisionSummary, b.RevisionSummary)
}
