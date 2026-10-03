package codepipeline

import (
	api "stackd/internal/awsapi/codepipeline"
	"testing"
)

func TestUpdatedDefinitionRetainsHistoryAndInvalidatesApprovalView(t *testing.T) {
	s, ctx, v, original := kernelFixture(t, "QUEUED")
	e := gateExecution(s, v, "execution", "QUEUED", 1)
	e.Actions = []ActionExecution{{
		ID: "source-action", StageName: "Source", ActionName: "Source", Status: "Succeeded",
		StageIndex: 0, ActionIndex: 0, Attempt: 1, StartedAt: e.StartedAt, UpdatedAt: e.StartedAt,
	}}
	e.Revisions = []SourceRevision{{ActionName: "Source", RevisionID: "original-version", CreatedAt: e.StartedAt}}
	advanceExecution(t, s, ctx, v, original, &e)
	token := e.Actions[1].ApprovalToken

	// Seed the committed update boundary: immutable v1 history, a current v2
	// declaration with an added stage, and invalidated old advancement.
	updated := original
	updated.Declaration = CloneDeclaration(original.Declaration)
	updated.Declaration.Version = new(api.PipelineVersion(2))
	added := updated.Declaration.Stages[1]
	added.Name = new(api.StageName("AfterUpdate"))
	updated.Declaration.Stages = append(updated.Declaration.Stages, added)
	v.Version = 2
	e.UpdatedDefinition = true
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutPipeline(v); err != nil {
			return err
		}
		if err := tx.PutDefinition(updated); err != nil {
			return err
		}
		return tx.PutExecution(e)
	}); err != nil {
		t.Fatal(err)
	}
	advanceExecution(t, s, ctx, v, original, &e)
	if e.Status != "InProgress" || e.Actions[1].Status != "InProgress" || !e.Due.IsZero() {
		t.Fatalf("update invented a historical terminal outcome or kept polling an invalid approval: %+v", e)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		state, err := s.getState(tx, &api.GetPipelineStateInput{Name: new(api.PipelineName(v.Name))})
		if err != nil {
			return err
		}
		if value(state.PipelineVersion) != 2 {
			t.Fatalf("current pipeline version: %+v", state)
		}
		source := state.StageStates[0].ActionStates[0]
		if source.LatestExecution == nil || text(source.LatestExecution.Status) != "Succeeded" || source.CurrentRevision == nil || text(source.CurrentRevision.RevisionId) != "original-version" {
			t.Fatalf("update lost retained source state: %+v", source)
		}
		gate := state.StageStates[1]
		approval := gate.ActionStates[0].LatestExecution
		if gate.LatestExecution == nil || text(gate.LatestExecution.Status) != "InProgress" || approval == nil || text(approval.Status) != "Failed" || approval.Token != nil {
			t.Fatalf("current approval projection: %+v", gate)
		}
		if state.StageStates[2].LatestExecution != nil || state.StageStates[2].ActionStates[0].LatestExecution != nil {
			t.Fatal("new stage inherited an unrelated old stage execution")
		}
		execution, err := s.getExecution(tx, &api.GetPipelineExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID))})
		if err != nil {
			return err
		}
		if value(execution.PipelineExecution.PipelineVersion) != 1 || text(execution.PipelineExecution.Status) != "InProgress" {
			t.Fatalf("update rewrote historical execution: %+v", execution)
		}
		history, err := s.listActions(tx, &api.ListActionExecutionsInput{PipelineName: new(api.PipelineName(v.Name)), Filter: &api.ActionExecutionFilter{PipelineExecutionId: new(api.PipelineExecutionId(e.ID))}})
		if err != nil {
			return err
		}
		found := false
		for _, action := range history.ActionExecutionDetails {
			if text(action.ActionName) == "Review" {
				found = true
				if text(action.Status) != "InProgress" {
					t.Fatalf("current-state cancellation leaked into historical action: %+v", action)
				}
			}
		}
		if !found {
			t.Fatal("update lost historical approval")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.approve(tx, &api.PutApprovalResultInput{
			PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")),
			ActionName: new(api.ActionName("Review")), Token: new(api.ApprovalToken(token)),
			Result: &api.ApprovalResult{Status: new(api.ApprovalStatus("Approved")), Summary: new(api.ApprovalSummary("stale approval"))},
		})
		if err == nil || wireError(err).Code != "InvalidApprovalTokenException" {
			t.Fatalf("old approval token remained authorized: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{
			PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Abandon: new(api.Boolean(true)),
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		retained, err := findExecution(r, v, e.ID)
		if err != nil {
			return err
		}
		if retained.Status != "Stopped" || retained.Actions[1].Status != "Abandoned" {
			t.Fatalf("explicit abandon failed after update: %+v", retained)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
