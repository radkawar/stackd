package codepipeline

import (
	"context"
	"errors"
	"stackd/clock"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
	"testing"
	"time"
)

func kernelFixture(t *testing.T, mode string) (*Service, context.Context, Pipeline, Definition) {
	t.Helper()
	sc := Scope{"aws", "111122223333", "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{
		Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region,
		PrincipalARN: "arn:aws:iam::111122223333:root", PrincipalID: sc.AccountID,
	})
	s := New(Config{Clock: clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))})
	t.Cleanup(func() { s.Close() })
	v := Pipeline{Scope: sc, Name: "release", Incarnation: "incarnation", Version: 1, Tags: map[string]string{}}
	action := func(name, provider, category string) api.ActionDeclaration {
		return api.ActionDeclaration{
			Name: new(api.ActionName(name)),
			ActionTypeId: &api.ActionTypeId{
				Provider: new(api.ActionProvider(provider)), Category: new(api.ActionCategory(category)),
				Owner: new(api.ActionOwner("AWS")), Version: new(api.Version("1")),
			},
			RunOrder: new(api.ActionRunOrder(1)), Configuration: api.ActionConfigurationMap{},
		}
	}
	d := Definition{
		Scope: sc, Incarnation: v.Incarnation,
		Declaration: api.PipelineDeclaration{
			Name:    new(api.PipelineName(v.Name)),
			RoleArn: new(api.RoleArn("arn:aws:iam::111122223333:role/pipeline")),
			Version: new(api.PipelineVersion(1)), ExecutionMode: new(api.ExecutionMode(mode)),
			ArtifactStore: &api.ArtifactStore{
				Type: new(api.ArtifactStoreType("S3")), Location: new(api.ArtifactStoreLocation("artifacts")),
			},
			Stages: api.PipelineStageDeclarationList{
				{Name: new(api.StageName("Source")), Actions: api.StageActionDeclarationList{action("Source", "S3", "Source")}},
				{Name: new(api.StageName("Gate")), Actions: api.StageActionDeclarationList{action("Review", "Manual", "Approval")}},
			},
		},
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutPipeline(v); err != nil {
			return err
		}
		return tx.PutDefinition(d)
	}); err != nil {
		t.Fatal(err)
	}
	return s, ctx, v, d
}
func gateExecution(s *Service, v Pipeline, id, mode string, sequence int64) Execution {
	return Execution{
		Scope: v.Scope, PipelineName: v.Name, Incarnation: v.Incarnation,
		ID: id, Version: 1, Attempt: 1, Mode: mode, Status: "InProgress", StageIndex: 1,
		StartedAt: s.clock.Now(), UpdatedAt: s.clock.Now(), Due: s.clock.Now(),
		Sequence: sequence, Generation: 1,
	}
}

func advanceExecution(t *testing.T, s *Service, ctx context.Context, v Pipeline, d Definition, e *Execution) {
	t.Helper()
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		req, err := s.advance(tx, v, d, e)
		if err != nil {
			return err
		}
		if req != nil {
			t.Fatalf("manual approval unexpectedly invoked external provider: %+v", req)
		}
		return tx.PutExecution(*e)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStageModesAndManualApproval(t *testing.T) {
	for _, mode := range []string{"SUPERSEDED", "QUEUED", "PARALLEL"} {
		t.Run(mode, func(t *testing.T) {
			s, ctx, v, d := kernelFixture(t, mode)
			older := gateExecution(s, v, "older", mode, 1)
			newer := gateExecution(s, v, "newer", mode, 2)
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutExecution(older); err != nil {
					return err
				}
				return tx.PutExecution(newer)
			}); err != nil {
				t.Fatal(err)
			}
			advanceExecution(t, s, ctx, v, d, &older)
			if mode == "SUPERSEDED" {
				if older.Status != "Superseded" || older.StageEntered {
					t.Fatalf("waiting execution was not superseded: %+v", older)
				}
			} else if !older.StageEntered || len(older.Actions) != 1 || older.Actions[0].Status != "InProgress" {
				t.Fatalf("older execution did not hold approval stage: %+v", older)
			}
			advanceExecution(t, s, ctx, v, d, &newer)
			if mode == "QUEUED" {
				if newer.StageEntered || len(newer.Actions) != 0 {
					t.Fatal("queued execution bypassed locked stage")
				}
				return
			}
			if !newer.StageEntered || newer.Actions[0].ApprovalToken == "" {
				t.Fatal("newer execution did not enter available approval stage")
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.approve(tx, &api.PutApprovalResultInput{
					PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
					ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(newer.Actions[0].ApprovalToken)),
					Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved")), Summary: new(api.ApprovalSummary("release approved"))},
				})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				var err error
				newer, err = findExecution(r, v, newer.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			advanceExecution(t, s, ctx, v, d, &newer)
			if newer.Status != "Succeeded" {
				t.Fatalf("approved execution did not finish: %+v", newer)
			}
		})
	}
}

func TestStopWaitAndAbandonFences(t *testing.T) {
	for _, abandon := range []bool{false, true} {
		t.Run(map[bool]string{false: "wait", true: "abandon"}[abandon], func(t *testing.T) {
			s, ctx, v, d := kernelFixture(t, "SUPERSEDED")
			e := gateExecution(s, v, "execution", "SUPERSEDED", 1)
			advanceExecution(t, s, ctx, v, d, &e)
			token := e.Actions[0].ApprovalToken
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{
					PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)),
					Abandon: new(api.Boolean(abandon)),
				})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				var err error
				e, err = findExecution(r, v, e.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			advanceExecution(t, s, ctx, v, d, &e)
			if abandon {
				if e.Status != "Stopped" || e.Actions[0].Status != "Abandoned" {
					t.Fatalf("abandon lost state: %+v", e)
				}
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					_, err := s.approve(tx, &api.PutApprovalResultInput{
						PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
						ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(token)),
						Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved")), Summary: new(api.ApprovalSummary("too late"))},
					})
					if err == nil || wireError(err).Code != "InvalidApprovalTokenException" {
						t.Fatalf("abandoned approval token was not invalidated: %v", err)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				return
			}
			if terminal(e.Status) {
				t.Fatalf("wait completed before active approval: %+v", e)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.approve(tx, &api.PutApprovalResultInput{
					PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
					ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(token)),
					Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved")), Summary: new(api.ApprovalSummary("approved"))},
				})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				var err error
				e, err = findExecution(r, v, e.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			advanceExecution(t, s, ctx, v, d, &e)
			if e.Status != "Stopped" || e.Actions[0].Status != "Succeeded" {
				t.Fatalf("wait completion lost successful approval: %+v", e)
			}
		})
	}
}

func TestClientTokenAndSourceBinding(t *testing.T) {
	s, ctx, v, d := kernelFixture(t, "QUEUED")
	d.Declaration.Stages[0].Actions[0].Configuration["AllowOverrideForS3ObjectKey"] = "true"
	overrides := api.SourceRevisionOverrideList{{
		ActionName: new(api.ActionName("Source")), RevisionType: new(api.SourceRevisionType("S3_OBJECT_KEY")),
		RevisionValue: new(api.Revision("overridden.zip")),
	}}
	var first string
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		first, err = s.startExecution(tx, v, d, "token", overrides, nil, "StartPipelineExecution")
		if err != nil {
			return err
		}
		again, err := s.startExecution(tx, v, d, "token", overrides, nil, "StartPipelineExecution")
		if err != nil {
			return err
		}
		if again != first {
			t.Fatal("idempotent start admitted another execution")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e := gateExecution(s, v, first, "QUEUED", 1)
	e.SourceOverrides = overrides
	e.Revisions = []SourceRevision{{ActionName: "Source", RevisionID: "original-version"}}
	a := ActionExecution{
		ID: "action", StageIndex: 0, ActionIndex: 0, ActionName: "Source",
		ResolvedConfiguration: api.ActionConfigurationMap{"S3ObjectKey": "initial.zip"},
	}
	request := actionRequest(v, d, e, a)
	if len(request.SourceRevisionOverrides) != 2 || text(request.SourceRevisionOverrides[0].RevisionValue) != "overridden.zip" || text(request.SourceRevisionOverrides[1].RevisionValue) != "original-version" {
		t.Fatalf("bound source lost object key/version: %+v", request.SourceRevisionOverrides)
	}
}

type rejectingEvents struct{ err error }

func (r rejectingEvents) PipelineStateChanged(context.Context, Pipeline, Execution) error {
	return r.err
}

func (r rejectingEvents) ActionStateChanged(context.Context, Pipeline, Execution, ActionExecution, api.ActionDeclaration) error {
	return r.err
}

func (r rejectingEvents) StageStateChanged(context.Context, Pipeline, Execution, string, string) error {
	return r.err
}

func TestStateAndEventFailureRollback(t *testing.T) {
	s, ctx, v, d := kernelFixture(t, "SUPERSEDED")
	rejected := errors.New("journal unavailable")
	s.events = rejectingEvents{rejected}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.startExecution(tx, v, d, "token", nil, nil, "StartPipelineExecution")
		return err
	})
	if !errors.Is(err, rejected) {
		t.Fatalf("event failure: %v", err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if len(rows) != 0 {
			t.Fatal("failed event committed execution")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRunOrderAndFailedActionRetry(t *testing.T) {
	s, ctx, v, d := kernelFixture(t, "QUEUED")
	second := d.Declaration.Stages[1].Actions[0]
	second.Name = new(api.ActionName("SecondReview"))
	second.RunOrder = new(api.ActionRunOrder(2))
	d.Declaration.Stages[1].Actions = append(d.Declaration.Stages[1].Actions, second)
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDefinition(d) }); err != nil {
		t.Fatal(err)
	}
	e := gateExecution(s, v, "execution", "QUEUED", 1)
	advanceExecution(t, s, ctx, v, d, &e)
	if len(e.Actions) != 1 || e.Actions[0].ActionName != "Review" {
		t.Fatal("later runOrder admitted before approval")
	}
	firstID := e.Actions[0].ID
	e.Actions[0].Status = "Succeeded"
	advanceExecution(t, s, ctx, v, d, &e)
	if len(e.Actions) != 2 || e.Actions[1].ActionName != "SecondReview" {
		t.Fatal("next runOrder did not advance")
	}
	failedID := e.Actions[1].ID
	e.Actions[1].Status = "Failed"
	advanceExecution(t, s, ctx, v, d, &e)
	if e.Status != "Failed" {
		t.Fatal("rejected second approval did not fail the pipeline")
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.retryStage(tx, &api.RetryStageExecutionInput{
			PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)),
			StageName: new(api.StageName("Gate")), RetryMode: new(api.StageRetryMode("FAILED_ACTIONS")),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		e, err = findExecution(r, v, e.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	advanceExecution(t, s, ctx, v, d, &e)
	first := latestAction(e, 1, 0)
	secondAttempt := latestAction(e, 1, 1)
	if first.ID != firstID || first.Status != "Succeeded" {
		t.Fatal("FAILED_ACTIONS retried a successful earlier group")
	}
	if secondAttempt.ID == failedID || secondAttempt.Attempt != 2 || secondAttempt.Status != "InProgress" {
		t.Fatalf("failed action did not get a new attempt: %+v", secondAttempt)
	}
	if len(e.Actions) != 3 || e.Actions[1].Status != "Failed" {
		t.Fatal("retry erased failed action history")
	}
}
