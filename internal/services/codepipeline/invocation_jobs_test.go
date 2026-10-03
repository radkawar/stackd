package codepipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
)

func invocationFixture(t *testing.T) (*Service, context.Context, Pipeline, Definition, Execution) {
	t.Helper()
	s, ctx, v, d := kernelFixture(t, "SUPERSEDED")
	a := &d.Declaration.Stages[1].Actions[0]
	a.ActionTypeId.Category = new(api.ActionCategory("Invoke"))
	a.ActionTypeId.Provider = new(api.ActionProvider("Lambda"))
	a.Configuration = api.ActionConfigurationMap{"FunctionName": "transform", "UserParameters": "release-42"}
	e := gateExecution(s, v, "execution", "SUPERSEDED", 1)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutDefinition(d); err != nil {
			return err
		}
		return tx.PutExecution(e)
	}); err != nil {
		t.Fatal(err)
	}
	return s, ctx, v, d, e
}

func runInvocationStep(t *testing.T, s *Service, ctx context.Context) {
	t.Helper()
	jobs := pipelineJobs{s}
	job, found, err := jobs.Next(ctx)
	if err != nil || !found {
		t.Fatalf("next invocation work: found=%v err=%v", found, err)
	}
	if delay := job.Due.Sub(s.clock.Now()); delay > 0 {
		if err := s.clock.(*clock.Manual).Advance(delay); err != nil {
			t.Fatal(err)
		}
	}
	if err := jobs.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
}

func readInvocation(t *testing.T, s *Service, ctx context.Context, sc Scope, id string) InvocationJob {
	t.Helper()
	var job InvocationJob
	if err := s.repository.View(ctx, func(r Reader) error {
		var found bool
		var err error
		job, found, err = r.InvocationJob(sc, id)
		if err == nil && !found {
			t.Fatal("invocation job disappeared")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return job
}

func TestInvocationCallbackBeforeDispatchAcknowledgment(t *testing.T) {
	s, ctx, v, _, e := invocationFixture(t)
	var id string
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		id = request.InvocationJob.ID
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.putJobSuccess(tx, &api.PutJobSuccessResultInput{JobId: new(api.JobId(id)), OutputVariables: api.OutputVariablesMap{"Release": "42"}})
			return err
		}); err != nil {
			return ActionResult{}, err
		}
		return ActionResult{Status: "InProgress", InvocationAccepted: true}, nil
	})
	runInvocationStep(t, s, ctx)
	if job := readInvocation(t, s, ctx, v.Scope, id); job.Status != "Succeeded" || job.OutputVariables["Release"] != "42" {
		t.Fatalf("dispatch acknowledgment overwrote callback: %+v", job)
	}
	retained := retainedNotification(t, s, ctx, v, e.ID)
	if retained.Actions[0].Status != "InProgress" {
		t.Fatalf("callback bypassed scheduled action completion: %+v", retained.Actions[0])
	}
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		if request.InvocationJob.Status != "Succeeded" {
			t.Fatalf("callback was lost on result consumption: %+v", request.InvocationJob)
		}
		return ActionResult{Status: "Succeeded", OutputVariables: request.InvocationJob.OutputVariables}, nil
	})
	runInvocationStep(t, s, ctx)
	runInvocationStep(t, s, ctx)
	retained = retainedNotification(t, s, ctx, v, e.ID)
	if retained.Status != "Succeeded" || retained.Actions[0].OutputVariables["Release"] != "42" {
		t.Fatalf("callback did not finish through action path: %+v", retained)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putJobSuccess(tx, &api.PutJobSuccessResultInput{JobId: new(api.JobId(id)), OutputVariables: api.OutputVariablesMap{"Release": "42"}})
		return err
	}); err != nil {
		t.Fatalf("identical terminal callback was not idempotent: %v", err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putJobSuccess(tx, &api.PutJobSuccessResultInput{JobId: new(api.JobId(id))})
		return err
	}); err == nil || wireError(err).Code != "InvalidJobStateException" {
		t.Fatalf("changed same-status callback was accepted: %v", err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putJobFailure(tx, &api.PutJobFailureResultInput{JobId: new(api.JobId(id)), FailureDetails: &api.FailureDetails{Type: new(api.FailureType("JobFailed")), Message: new(api.Message("too late"))}})
		return err
	}); err == nil || wireError(err).Code != "InvalidJobStateException" {
		t.Fatalf("completed callback accepted a contradictory outcome: %v", err)
	}
}

func TestInvocationContinuationReopenKeepsActionAndArtifactOwnership(t *testing.T) {
	s, ctx, v, d, e := invocationFixture(t)
	d.Declaration.Stages[1].Actions[0].OutputArtifacts = api.OutputArtifactList{{Name: new(api.ArtifactName("Produced"))}}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDefinition(d) }); err != nil {
		t.Fatal(err)
	}
	var first ActionRequest
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		first = request
		return ActionResult{Status: "InProgress", InvocationAccepted: true}, nil
	})
	runInvocationStep(t, s, ctx)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putJobSuccess(tx, &api.PutJobSuccessResultInput{JobId: new(api.JobId(first.InvocationJob.ID)), ContinuationToken: new(api.ContinuationToken("resume-42")), OutputVariables: api.OutputVariablesMap{"Release": "42"}})
		return err
	}); err == nil || wireError(err).Code != "ValidationException" {
		t.Fatalf("continuation and output variables were accepted together: %v", err)
	}
	if err := s.clock.(*clock.Manual).Advance(19 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putJobSuccess(tx, &api.PutJobSuccessResultInput{JobId: new(api.JobId(first.InvocationJob.ID)), ContinuationToken: new(api.ContinuationToken("resume-42"))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putJobSuccess(tx, &api.PutJobSuccessResultInput{JobId: new(api.JobId(first.InvocationJob.ID)), ContinuationToken: new(api.ContinuationToken("resume-42"))})
		return err
	}); err != nil {
		t.Fatalf("identical continuation replay was not idempotent: %v", err)
	}
	reopened := New(Config{Repository: s.repository, Clock: s.clock})
	t.Cleanup(func() { reopened.Close() })
	var next ActionRequest
	reopened.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		next = request
		return ActionResult{Status: "InProgress", InvocationAccepted: true}, nil
	})
	runInvocationStep(t, reopened, ctx)
	if next.InvocationJob.ID == first.InvocationJob.ID || next.InvocationJob.ContinuationToken != "resume-42" || next.InvocationJob.Sequence != 2 || next.ActionExecutionID != first.ActionExecutionID || next.OutputArtifacts[0] != first.OutputArtifacts[0] || !next.InvocationJob.ActionExpiresAt.Equal(first.InvocationJob.ActionExpiresAt) || !next.InvocationJob.ExpiresAt.Equal(s.clock.Now().Add(20*time.Minute)) {
		t.Fatalf("continuation lost ownership: first=%+v next=%+v", first.InvocationJob, next.InvocationJob)
	}
	if job := readInvocation(t, reopened, ctx, v.Scope, first.InvocationJob.ID); job.Status != "Continued" {
		t.Fatalf("prior job remained callback-active: %+v", job)
	}
	if err := reopened.repository.View(ctx, func(r Reader) error {
		jobs, err := r.InvocationJobs(v.Scope, first.ActionExecutionID)
		if err != nil {
			return err
		}
		if len(jobs) != 2 {
			t.Fatalf("identical continuation created duplicate work: %+v", jobs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	retained := retainedNotification(t, reopened, ctx, v, e.ID)
	if retained.Actions[0].Status != "InProgress" || retained.Actions[0].OutputArtifacts[0].VersionID != "" {
		t.Fatalf("continuation created counterfeit artifact completion: %+v", retained.Actions[0])
	}
	if err := reopened.repository.Update(ctx, func(tx Transaction) error {
		_, err := reopened.putJobSuccess(tx, &api.PutJobSuccessResultInput{JobId: new(api.JobId(first.InvocationJob.ID))})
		return err
	}); err == nil || wireError(err).Code != "InvalidJobStateException" {
		t.Fatalf("prior continuation accepted another callback: %v", err)
	}
}

func TestInvocationCallbacksFenceScopeStopDeleteAndRetry(t *testing.T) {
	for _, mutation := range []string{"account", "region", "abandon", "delete-recreate", "retry", "update", "expire"} {
		t.Run(mutation, func(t *testing.T) {
			s, ctx, v, _, e := invocationFixture(t)
			var id string
			s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
				id = request.InvocationJob.ID
				return ActionResult{Status: "InProgress", InvocationAccepted: true}, nil
			})
			runInvocationStep(t, s, ctx)
			callbackContext := ctx
			if mutation == "account" || mutation == "region" {
				metadata := awsctx.FromContext(ctx)
				if mutation == "account" {
					metadata.AccountID = "999900001111"
					metadata.PrincipalARN = "arn:aws:iam::999900001111:root"
					metadata.PrincipalID = metadata.AccountID
				} else {
					metadata.Region = "us-west-2"
				}
				callbackContext = awsctx.WithMetadata(ctx, metadata)
			}
			if mutation == "expire" {
				if err := s.clock.(*clock.Manual).Advance(time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				switch mutation {
				case "abandon", "retry":
					if _, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Abandon: new(api.Boolean(true))}); err != nil {
						return err
					}
					if mutation == "retry" {
						_, err := s.retryStage(tx, &api.RetryStageExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), StageName: new(api.StageName("Gate")), RetryMode: new(api.StageRetryMode("ALL_ACTIONS"))})
						return err
					}
				case "delete-recreate":
					if err := tx.DeletePipeline(v.Scope, v.Name); err != nil {
						return err
					}
					v.Incarnation = "replacement"
					return tx.PutPipeline(v)
				case "update":
					current, err := findExecution(tx, v, e.ID)
					if err != nil {
						return err
					}
					current.UpdatedDefinition = true
					return tx.PutExecution(current)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			err := s.repository.Update(callbackContext, func(tx Transaction) error {
				_, err := s.putJobSuccess(tx, &api.PutJobSuccessResultInput{JobId: new(api.JobId(id))})
				return err
			})
			wantJobStatus := "Running"
			if mutation == "abandon" {
				if err != nil {
					t.Fatalf("native accepts callbacks after abandonment: %v", err)
				}
				wantJobStatus = "Succeeded"
				stopped := retainedNotification(t, s, ctx, v, e.ID)
				if stopped.Status != "Stopped" || stopped.Actions[0].Status != "Abandoned" || !stopped.Due.IsZero() {
					t.Fatalf("accepted callback revived abandoned execution: %+v", stopped)
				}
			} else if err == nil || wireError(err).Code != "JobNotFoundException" {
				t.Fatalf("%s allowed fenced callback: %v", mutation, err)
			}
			if job := readInvocation(t, s, ctx, v.Scope, id); job.Status != wantJobStatus {
				t.Fatalf("fenced callback changed job unexpectedly: %+v", job)
			}
		})
	}
}

func TestInvocationInterruptedDispatchRecoversWithoutAutomaticSuccess(t *testing.T) {
	s, ctx, v, _, e := invocationFixture(t)
	interrupted, cancel := context.WithCancel(ctx)
	defer cancel()
	var first string
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		first = request.InvocationJob.ID
		cancel()
		return ActionResult{Status: "InProgress", InvocationAccepted: true}, nil
	})
	if err := (pipelineJobs{s}).Run(interrupted, executionJob(e)); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted dispatch: %v", err)
	}
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		if request.InvocationJob.ID != first {
			t.Fatal("unacknowledged dispatch invented another job")
		}
		return ActionResult{Status: "InProgress", InvocationAccepted: request.InvocationJob.Status == "Ready"}, nil
	})
	runInvocationStep(t, s, ctx)
	runInvocationStep(t, s, ctx)
	retained := retainedNotification(t, s, ctx, v, e.ID)
	if retained.Status != "InProgress" || retained.Actions[0].Status != "InProgress" || readInvocation(t, s, ctx, v.Scope, first).Status != "Running" {
		t.Fatalf("normal Lambda return incorrectly completed an action: %+v", retained)
	}
}

func TestInvocationStopWaitPreservesDispatchAndFailureReplay(t *testing.T) {
	s, ctx, v, d, e := invocationFixture(t)
	var id string
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		id = request.InvocationJob.ID
		err := s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Abandon: new(api.Boolean(false))})
			return err
		})
		return ActionResult{Status: "InProgress", InvocationAccepted: true}, err
	})
	runInvocationStep(t, s, ctx)
	if job := readInvocation(t, s, ctx, v.Scope, id); job.Status != "Running" {
		t.Fatalf("stop-wait discarded an accepted dispatch: %+v", job)
	}
	failed := &api.PutJobFailureResultInput{JobId: new(api.JobId(id)), FailureDetails: &api.FailureDetails{
		Type: new(api.FailureType("JobFailed")), Message: new(api.Message("transformation failed")), ExternalExecutionId: new(api.ExecutionId("worker-42")),
	}}
	for range 2 {
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.putJobFailure(tx, failed)
			return err
		}); err != nil {
			t.Fatalf("failure callback/replay: %v", err)
		}
	}
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		if request.InvocationJob.Status != "Failed" {
			t.Fatalf("failure callback was lost: %+v", request.InvocationJob)
		}
		return ActionResult{Status: "Failed", ErrorCode: text(request.InvocationJob.FailureDetails.Type), ErrorMessage: text(request.InvocationJob.FailureDetails.Message), Summary: text(request.InvocationJob.FailureDetails.Message)}, nil
	})
	runInvocationStep(t, s, ctx)
	runInvocationStep(t, s, ctx)
	stopped := retainedNotification(t, s, ctx, v, e.ID)
	if stopped.Status != "Stopped" || stopped.Actions[0].Status != "Failed" || stopped.Actions[0].ErrorMessage != "transformation failed" || !stopped.Due.IsZero() {
		t.Fatalf("stop-wait did not settle its admitted Lambda action: %+v", stopped)
	}
	detail := actionDetail(stopped, stopped.Actions[0], d)
	if detail.Output.ExecutionResult.ErrorDetails.Message != nil || text(detail.Output.ExecutionResult.ExternalExecutionSummary) != "transformation failed" {
		t.Fatalf("Lambda history must put failure text only in its summary: %+v", detail.Output.ExecutionResult)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		state, err := s.getState(tx, &api.GetPipelineStateInput{Name: new(api.PipelineName(v.Name))})
		if err != nil {
			return err
		}
		current := state.StageStates[1].ActionStates[0].LatestExecution
		if current == nil || current.Summary != nil || text(current.ErrorDetails.Message) != "transformation failed" {
			t.Fatalf("Lambda current-state failure must use error details, not summary: %+v", current)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestInvocationAcceptedResultReplayAfterDeletion(t *testing.T) {
	s, ctx, v, _, e := invocationFixture(t)
	var id string
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		id = request.InvocationJob.ID
		return ActionResult{Status: "InProgress", InvocationAccepted: true}, nil
	})
	runInvocationStep(t, s, ctx)
	result := &api.PutJobSuccessResultInput{JobId: new(api.JobId(id)), OutputVariables: api.OutputVariablesMap{"Release": "42"}}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Abandon: new(api.Boolean(true))}); err != nil {
			return err
		}
		if _, err := s.putJobSuccess(tx, result); err != nil {
			return err
		}
		return tx.DeletePipeline(v.Scope, v.Name)
	}); err != nil {
		t.Fatal(err)
	}
	before := readInvocation(t, s, ctx, v.Scope, id)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putJobSuccess(tx, result)
		return err
	}); err != nil {
		t.Fatalf("accepted callback replay after deletion: %v", err)
	}
	after := readInvocation(t, s, ctx, v.Scope, id)
	retained := retainedNotification(t, s, ctx, v, e.ID)
	if after.Generation != before.Generation || after.Status != "Succeeded" || retained.Status != "Stopped" || retained.Actions[0].Status != "Abandoned" || len(retained.Actions[0].OutputVariables) != 0 || !retained.Due.IsZero() {
		t.Fatalf("deleted callback replay revived execution: job=%+v execution=%+v", after, retained)
	}
}
