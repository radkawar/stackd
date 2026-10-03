package codepipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/codepipeline"
)

type approvalExecutorFunc func(context.Context, ActionRequest) (ActionResult, error)

func (f approvalExecutorFunc) Execute(ctx context.Context, request ActionRequest) (ActionResult, error) {
	return f(ctx, request)
}

func notificationFixture(t *testing.T) (*Service, context.Context, Pipeline, Definition, Execution) {
	t.Helper()
	s, ctx, v, d := kernelFixture(t, "SUPERSEDED")
	d.Declaration.Stages[1].Actions[0].Configuration = api.ActionConfigurationMap{
		"NotificationArn": "arn:aws:sns:us-east-1:111122223333:approvals",
		"CustomData":      "Review #{codepipeline.PipelineExecutionId}",
	}
	d.Declaration.Stages[1].Actions[0].TimeoutInMinutes = new(api.ActionTimeout(5))
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

func retainedNotification(t *testing.T, s *Service, ctx context.Context, v Pipeline, id string) Execution {
	t.Helper()
	var e Execution
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		e, err = findExecution(r, v, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

func runNotificationJob(t *testing.T, s *Service, ctx context.Context) {
	t.Helper()
	jobs := pipelineJobs{s}
	job, found, err := jobs.Next(ctx)
	if err != nil || !found {
		t.Fatalf("notification job: found=%v error=%v", found, err)
	}
	if err := jobs.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalNotificationInterruptedClaimRecovery(t *testing.T) {
	s, ctx, v, _, e := notificationFixture(t)
	started := s.clock.Now()
	interrupted, cancel := context.WithCancel(ctx)
	defer cancel()
	var first ActionRequest
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		first = request
		cancel()
		return ActionResult{}, context.Canceled
	})
	jobs := pipelineJobs{s}
	if err := jobs.Run(interrupted, executionJob(e)); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted notification: %v", err)
	}
	claimed := retainedNotification(t, s, ctx, v, e.ID)
	a := claimed.Actions[0]
	if a.Status != "InProgress" || a.ApprovalToken == "" || a.ApprovalNotificationID != "" || !claimed.Due.Equal(started.Add(30*time.Second)) {
		t.Fatalf("publication claim was not recoverable: %+v", claimed)
	}
	if !first.ApprovalExpiresAt.Equal(started.Add(5*time.Minute)) || first.Action.Configuration["CustomData"] != "Review execution" {
		t.Fatalf("admission did not bind approval deadline/configuration: %+v", first)
	}
	calls := 0
	reopened := New(Config{Repository: s.repository, Clock: s.clock, Executor: approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		calls++
		if request.ApprovalToken != a.ApprovalToken || !request.ApprovalExpiresAt.Equal(first.ApprovalExpiresAt) || request.Action.Configuration["CustomData"] != first.Action.Configuration["CustomData"] {
			t.Fatalf("recovery changed the outstanding approval: %+v", request)
		}
		return ActionResult{Status: "InProgress", ApprovalNotificationID: "sns-message", ExternalExecutionID: "must-not-leak"}, nil
	})})
	t.Cleanup(func() { reopened.Close() })
	runNotificationJob(t, reopened, ctx)
	if calls != 0 {
		t.Fatal("reopen bypassed an unexpired publication claim")
	}
	if err := s.clock.(*clock.Manual).Advance(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, reopened, ctx)
	published := retainedNotification(t, reopened, ctx, v, e.ID)
	if calls != 1 || published.Actions[0].ApprovalNotificationID != "sns-message" || published.Actions[0].ExternalExecutionID != "" || !published.Actions[0].StartedAt.Equal(started) {
		t.Fatalf("recovery lost notification ownership: %+v; calls=%d", published, calls)
	}
	if err := s.clock.(*clock.Manual).Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, reopened, ctx)
	if calls != 1 {
		t.Fatal("completed publication was polled again")
	}
}

func TestApprovalNotificationPendingClaimExpires(t *testing.T) {
	s, ctx, v, d, e := notificationFixture(t)
	// Recover a retained action whose publication claim reaches its deadline.
	now := s.clock.Now()
	e.StageEntered = true
	e.Actions = []ActionExecution{{
		ID: "approval", StageName: "Gate", ActionName: "Review", StageIndex: 1,
		Status: "InProgress", ApprovalToken: "approval", StartedAt: now.Add(-5*time.Minute + 10*time.Second),
		UpdatedAt: now, ResolvedConfiguration: d.Declaration.Stages[1].Actions[0].Configuration,
	}}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutExecution(e) }); err != nil {
		t.Fatal(err)
	}
	interrupted, cancel := context.WithCancel(ctx)
	defer cancel()
	calls := 0
	s.executor = approvalExecutorFunc(func(context.Context, ActionRequest) (ActionResult, error) {
		calls++
		cancel()
		return ActionResult{}, context.Canceled
	})
	if err := (pipelineJobs{s}).Run(interrupted, executionJob(e)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	claimed := retainedNotification(t, s, ctx, v, e.ID)
	if !claimed.Due.Equal(now.Add(10 * time.Second)) {
		t.Fatalf("claim delayed approval expiration: %v", claimed.Due)
	}
	if err := s.clock.(*clock.Manual).Advance(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, s, ctx)
	expired := retainedNotification(t, s, ctx, v, e.ID)
	if calls != 1 || expired.Actions[0].Status != "Failed" || expired.Actions[0].ErrorCode != "ApprovalTimedOut" || expired.Actions[0].ApprovalNotificationID != "" {
		t.Fatalf("expired approval was republished: %+v; calls=%d", expired, calls)
	}
}

func TestApprovalNotificationResultFences(t *testing.T) {
	for _, mutation := range []string{"update", "abandon", "approve", "expire"} {
		t.Run(mutation, func(t *testing.T) {
			s, ctx, v, d, e := notificationFixture(t)
			calls := 0
			s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
				calls++
				if mutation == "expire" {
					if err := s.clock.(*clock.Manual).Advance(5 * time.Minute); err != nil {
						t.Fatal(err)
					}
				} else if err := s.repository.Update(ctx, func(tx Transaction) error {
					switch mutation {
					case "update":
						current, err := findExecution(tx, v, e.ID)
						if err != nil {
							return err
						}
						current.UpdatedDefinition = true
						current.Generation++
						current.Due = s.clock.Now()
						return tx.PutExecution(current)
					case "abandon":
						_, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Abandon: new(api.Boolean(true))})
						return err
					default:
						_, err := s.approve(tx, &api.PutApprovalResultInput{PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")), ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(request.ApprovalToken)), Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved")), Summary: new(api.ApprovalSummary("approved while publishing"))}})
						return err
					}
				}); err != nil {
					t.Fatal(err)
				}
				return ActionResult{Status: "InProgress", ApprovalNotificationID: "late-publication"}, nil
			})
			runNotificationJob(t, s, ctx)
			retained := retainedNotification(t, s, ctx, v, e.ID)
			advanceExecution(t, s, ctx, v, d, &retained)
			a := retained.Actions[0]
			switch mutation {
			case "update":
				if !retained.Due.IsZero() || a.Status != "InProgress" || a.ApprovalNotificationID != "" {
					t.Fatalf("update fence accepted notification result: %+v", retained)
				}
			case "abandon":
				if retained.Status != "Stopped" || a.Status != "Abandoned" || a.ApprovalNotificationID != "" {
					t.Fatalf("abandon fence resurrected approval: %+v", retained)
				}
			case "approve":
				if retained.Status != "Succeeded" || a.Status != "Succeeded" || a.Summary != "approved while publishing" || a.ExternalExecutionID != a.ID {
					t.Fatalf("notification result replaced approval: %+v", retained)
				}
			case "expire":
				if retained.Status != "Failed" || a.Status != "Failed" || a.ErrorCode != "ApprovalTimedOut" {
					t.Fatalf("late publication extended approval lifetime: %+v", retained)
				}
			}
			if calls != 1 {
				t.Fatal("invalidated approval was republished")
			}
		})
	}
}

func TestApprovalNotificationRetryOwnsNewPublication(t *testing.T) {
	s, ctx, v, d, e := notificationFixture(t)
	calls := 0
	s.executor = approvalExecutorFunc(func(context.Context, ActionRequest) (ActionResult, error) {
		calls++
		return ActionResult{Status: "InProgress", ApprovalNotificationID: "notification"}, nil
	})
	runNotificationJob(t, s, ctx)
	first := retainedNotification(t, s, ctx, v, e.ID).Actions[0]
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.approve(tx, &api.PutApprovalResultInput{PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")), ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(first.ApprovalToken)), Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Rejected")), Summary: new(api.ApprovalSummary("retry required"))}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e = retainedNotification(t, s, ctx, v, e.ID)
	advanceExecution(t, s, ctx, v, d, &e)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.retryStage(tx, &api.RetryStageExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), StageName: new(api.StageName("Gate")), RetryMode: new(api.StageRetryMode("FAILED_ACTIONS"))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pending := retainedNotification(t, s, ctx, v, e.ID).Actions[1]
	if pending.ApprovalToken != "" || pending.ApprovalNotificationID != "" || pending.ID == first.ID {
		t.Fatalf("retry inherited previous publication: %+v", pending)
	}
	runNotificationJob(t, s, ctx)
	retried := retainedNotification(t, s, ctx, v, e.ID).Actions[1]
	if calls != 2 || retried.ApprovalToken == first.ApprovalToken || retried.ApprovalNotificationID != "notification" || retried.Status != "InProgress" {
		t.Fatalf("retry did not own a new approval: %+v; calls=%d", retried, calls)
	}
}

func TestApprovalNotificationStopWaitDuringPublication(t *testing.T) {
	s, ctx, v, _, e := notificationFixture(t)
	publications := 0
	s.executor = approvalExecutorFunc(func(context.Context, ActionRequest) (ActionResult, error) {
		publications++
		if publications == 1 {
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{
					PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)),
					Abandon: new(api.Boolean(false)),
				})
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		return ActionResult{Status: "InProgress", ApprovalNotificationID: "sns-message"}, nil
	})
	runNotificationJob(t, s, ctx)
	waiting := retainedNotification(t, s, ctx, v, e.ID)
	if waiting.Status != "Stopping" || waiting.Actions[0].Status != "InProgress" || waiting.Actions[0].ApprovalNotificationID != "sns-message" {
		t.Fatalf("stop-and-wait discarded completed publication: %+v", waiting)
	}
	if err := s.clock.(*clock.Manual).Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, s, ctx)
	if publications != 1 {
		t.Fatalf("stop-and-wait republished an admitted approval: %d publications", publications)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.approve(tx, &api.PutApprovalResultInput{
			PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
			ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(waiting.Actions[0].ApprovalToken)),
			Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved")), Summary: new(api.ApprovalSummary("finish admitted work"))},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, s, ctx)
	stopped := retainedNotification(t, s, ctx, v, e.ID)
	if stopped.Status != "Stopped" || stopped.Actions[0].Status != "Succeeded" || stopped.Actions[0].ApprovalNotificationID != "sns-message" {
		t.Fatalf("stop-and-wait lost approval outcome: %+v", stopped)
	}
}

func TestApprovalNotificationParallelGroupSurvivesPublicationFailure(t *testing.T) {
	s, ctx, v, d, e := notificationFixture(t)
	first := d.Declaration.Stages[1].Actions[0]
	peer := first
	peer.Name = new(api.ActionName("Peer"))
	later := first
	later.Name = new(api.ActionName("Later"))
	later.RunOrder = new(api.ActionRunOrder(2))
	d.Declaration.Stages[1].Actions = append(d.Declaration.Stages[1].Actions, peer, later)
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDefinition(d) }); err != nil {
		t.Fatal(err)
	}
	var publications []string
	s.executor = approvalExecutorFunc(func(_ context.Context, request ActionRequest) (ActionResult, error) {
		name := text(request.Action.Name)
		publications = append(publications, name)
		if name == "Review" {
			return ActionResult{Status: "Failed", ErrorCode: "ConfigurationError", ErrorMessage: "Topic does not exist"}, nil
		}
		return ActionResult{Status: "InProgress", ApprovalNotificationID: "peer-notification"}, nil
	})
	runNotificationJob(t, s, ctx)
	runNotificationJob(t, s, ctx)
	waiting := retainedNotification(t, s, ctx, v, e.ID)
	if len(publications) != 2 || publications[0] != "Review" || publications[1] != "Peer" ||
		len(waiting.Actions) != 2 || waiting.Status != "InProgress" {
		t.Fatalf("publication failure lost its parallel peer or admitted a later runOrder: publications=%v execution=%+v", publications, waiting)
	}
	if waiting.Actions[0].Status != "Failed" || waiting.Actions[1].Status != "InProgress" || waiting.Actions[1].ApprovalNotificationID != "peer-notification" {
		t.Fatalf("parallel approvals lost independent publication outcomes: %+v", waiting.Actions)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.approve(tx, &api.PutApprovalResultInput{
			PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
			ActionName: peer.Name, Token: new(api.ApprovalToken(waiting.Actions[1].ApprovalToken)),
			Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved")), Summary: new(api.ApprovalSummary("parallel peer complete"))},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, s, ctx)
	failed := retainedNotification(t, s, ctx, v, e.ID)
	if failed.Status != "Failed" || len(failed.Actions) != 2 || failed.Actions[1].Status != "Succeeded" || len(publications) != 2 {
		t.Fatalf("failed parallel group did not settle before the later runOrder: %+v; publications=%v", failed, publications)
	}
}

func TestApprovalNotificationStopWaitKeepsAdmittedApproval(t *testing.T) {
	s, ctx, v, d, e := notificationFixture(t)
	// Retain admission as if the process stopped before executing its claim.
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		request, err := s.advance(tx, v, d, &e)
		if err != nil {
			return err
		}
		if request == nil {
			t.Fatal("notification admission did not produce work")
		}
		return tx.PutExecution(e)
	}); err != nil {
		t.Fatal(err)
	}
	token := e.Actions[0].ApprovalToken
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{
			PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)),
			Abandon: new(api.Boolean(false)),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	publications := 0
	s.executor = approvalExecutorFunc(func(context.Context, ActionRequest) (ActionResult, error) {
		publications++
		return ActionResult{Status: "InProgress", ApprovalNotificationID: "sns-message"}, nil
	})
	runNotificationJob(t, s, ctx)
	waiting := retainedNotification(t, s, ctx, v, e.ID)
	if waiting.Status != "Stopping" || waiting.Actions[0].Status != "InProgress" || waiting.Actions[0].ApprovalToken != token || waiting.Actions[0].ApprovalNotificationID != "sns-message" {
		t.Fatalf("stop-and-wait discarded admitted approval: %+v", waiting)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.approve(tx, &api.PutApprovalResultInput{
			PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
			ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(token)),
			Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved")), Summary: new(api.ApprovalSummary("finish admitted work"))},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, s, ctx)
	stopped := retainedNotification(t, s, ctx, v, e.ID)
	if publications != 1 || stopped.Status != "Stopped" || stopped.Actions[0].Status != "Succeeded" {
		t.Fatalf("stop-and-wait lost approval completion: %+v; publications=%d", stopped, publications)
	}
}

func TestApprovalNotificationFailureSettlesAndHidesToken(t *testing.T) {
	s, ctx, v, d, e := notificationFixture(t)
	const denied = "The Pipeline or Action role does not have permission to publish to topics in Amazon SNS. Add the sns:Publish permission to the role’s policy, and then try again."
	s.executor = approvalExecutorFunc(func(context.Context, ActionRequest) (ActionResult, error) {
		return ActionResult{Status: "Failed", ErrorCode: "PermissionError", ErrorMessage: denied, Summary: denied}, nil
	})
	runNotificationJob(t, s, ctx)
	runNotificationJob(t, s, ctx)
	failed := retainedNotification(t, s, ctx, v, e.ID)
	a := failed.Actions[0]
	if failed.Status != "Failed" || a.Status != "Failed" || a.ApprovalNotificationID != "" || a.ExternalExecutionID != a.ID {
		t.Fatalf("failed publication did not fail its approval attempt: %+v", failed)
	}
	history := actionDetail(failed, a, d).Output.ExecutionResult
	if text(history.ExternalExecutionId) != a.ID || text(history.ExternalExecutionSummary) != denied || history.ErrorDetails == nil || text(history.ErrorDetails.Code) != "PermissionError" || history.ErrorDetails.Message != nil {
		t.Fatalf("notification failure history differs from native shape: %+v", history)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		state, err := s.getState(tx, &api.GetPipelineStateInput{Name: new(api.PipelineName(v.Name))})
		if err != nil {
			return err
		}
		current := state.StageStates[1].ActionStates[0].LatestExecution
		if current == nil || text(current.Status) != "Failed" || current.Token != nil || current.ExternalExecutionId != nil || current.LastStatusChange != nil || current.Summary != nil || current.ErrorDetails == nil || text(current.ErrorDetails.Message) != denied {
			t.Fatalf("failed notification exposed a live approval or history-only fields: %+v", current)
		}
		_, err = s.approve(tx, &api.PutApprovalResultInput{
			PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
			ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(a.ID)),
			Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved"))},
		})
		if err == nil || wireError(err).Code != "ApprovalAlreadyCompletedException" {
			t.Fatalf("failed publication remained approvable: %v", err)
		}
		_, err = s.retryStage(tx, &api.RetryStageExecutionInput{
			PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)),
			StageName: new(api.StageName("Gate")), RetryMode: new(api.StageRetryMode("FAILED_ACTIONS")),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.executor = approvalExecutorFunc(func(context.Context, ActionRequest) (ActionResult, error) {
		return ActionResult{Status: "InProgress", ApprovalNotificationID: "retry-publication"}, nil
	})
	runNotificationJob(t, s, ctx)
	retried := retainedNotification(t, s, ctx, v, e.ID).Actions[1]
	if retried.Status != "InProgress" || retried.ApprovalToken == a.ApprovalToken || retried.ApprovalNotificationID != "retry-publication" || retried.ErrorCode != "" {
		t.Fatalf("retry retained failed publication state: %+v", retried)
	}
}

func TestApprovalWithoutNotificationNeedsNoExecutor(t *testing.T) {
	s, ctx, v, _ := kernelFixture(t, "SUPERSEDED")
	e := gateExecution(s, v, "execution", "SUPERSEDED", 1)
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutExecution(e) }); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, s, ctx)
	waiting := retainedNotification(t, s, ctx, v, e.ID)
	if waiting.Actions[0].Status != "InProgress" || waiting.Actions[0].ApprovalToken == "" || waiting.Actions[0].ErrorCode != "" || waiting.Actions[0].ApprovalNotificationID != "" {
		t.Fatalf("manual approval without SNS required an executor: %+v", waiting)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.approve(tx, &api.PutApprovalResultInput{
			PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
			ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(waiting.Actions[0].ApprovalToken)),
			Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved"))},
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	runNotificationJob(t, s, ctx)
	if completed := retainedNotification(t, s, ctx, v, e.ID); completed.Status != "Succeeded" {
		t.Fatalf("manual approval without SNS did not complete: %+v", completed)
	}
}

type approvalAdmissionRoles struct{}

func (approvalAdmissionRoles) Validate(context.Context, string, string) error { return nil }

func TestApprovalNotificationARNAdmission(t *testing.T) {
	s, ctx, _, d := kernelFixture(t, "SUPERSEDED")
	s.roles = approvalAdmissionRoles{}
	source := &d.Declaration.Stages[0].Actions[0]
	source.Configuration = api.ActionConfigurationMap{"S3Bucket": "source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}
	source.OutputArtifacts = api.OutputArtifactList{{Name: new(api.ArtifactName("Source"))}}
	for _, tc := range []struct {
		name, topic string
		rejected    bool
	}{
		{name: "no-notification"},
		{name: "same-region", topic: "arn:aws:sns:us-east-1:111122223333:approvals"},
		{name: "cross-account", topic: "arn:aws:sns:us-east-1:000000000000:approvals"},
		{name: "fifo", topic: "arn:aws:sns:us-east-1:111122223333:approvals.fifo"},
		{name: "missing-topic", topic: "arn:aws:sns:us-east-1:111122223333:not-created"},
		{name: "malformed", topic: "not-an-arn", rejected: true},
		{name: "wrong-service", topic: "arn:aws:sqs:us-east-1:111122223333:approvals", rejected: true},
		{name: "cross-region", topic: "arn:aws:sns:us-west-2:111122223333:approvals", rejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declaration := CloneDeclaration(d.Declaration)
			declaration.Stages[1].Actions[0].Configuration = api.ActionConfigurationMap{"NotificationArn": api.ActionConfigurationValue(tc.topic)}
			err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.admitDefinition(tx, &declaration, 1)
				return err
			})
			if tc.rejected {
				if err == nil || wireError(err).Code != "InvalidActionDeclarationException" {
					t.Fatalf("invalid notification topic admitted: %v", err)
				}
			} else if err != nil {
				t.Fatalf("native-supported notification topic rejected: %v", err)
			}
		})
	}
}
