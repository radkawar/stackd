package codepipeline

import (
	"encoding/json"
	"os"
	"testing"

	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
)

func TestApprovalOutcomeHistoryAndCurrentProjection(t *testing.T) {
	for _, result := range []string{"Approved", "Rejected"} {
		t.Run(result, func(t *testing.T) {
			s, ctx, v, d := kernelFixture(t, "QUEUED")
			e := gateExecution(s, v, "execution", "QUEUED", 1)
			advanceExecution(t, s, ctx, v, d, &e)
			a := e.Actions[0]
			actor := awsctx.FromContext(ctx).PrincipalARN
			status := "Succeeded"
			if result == "Rejected" {
				status = "Failed"
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.approve(tx, &api.PutApprovalResultInput{
					PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName(a.StageName)),
					ActionName: new(api.ActionName(a.ActionName)), Token: new(api.ApprovalToken(a.ApprovalToken)),
					Result: &api.ApprovalResult{Status: new(api.ApprovalStatus(result)), Summary: new(api.ApprovalSummary("release decision"))},
				})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				history, err := s.listActions(tx, &api.ListActionExecutionsInput{
					PipelineName: new(api.PipelineName(v.Name)),
					Filter:       &api.ActionExecutionFilter{PipelineExecutionId: new(api.PipelineExecutionId(e.ID))},
				})
				if err != nil {
					return err
				}
				if len(history.ActionExecutionDetails) != 1 {
					t.Fatalf("approval history lost its action: %+v", history)
				}
				detail := history.ActionExecutionDetails[0]
				outcome := detail.Output.ExecutionResult
				if text(detail.Status) != status || text(detail.UpdatedBy) != actor || text(outcome.ExternalExecutionId) != a.ID || outcome.ErrorDetails != nil {
					t.Fatalf("approval history contract: %+v result=%+v", detail, outcome)
				}
				state, err := s.getState(tx, &api.GetPipelineStateInput{Name: new(api.PipelineName(v.Name))})
				if err != nil {
					return err
				}
				current := state.StageStates[1].ActionStates[0].LatestExecution
				if current == nil || text(current.Status) != status || text(current.LastUpdatedBy) != actor || current.ErrorDetails != nil || current.ExternalExecutionId != nil || current.Token != nil {
					t.Fatalf("approval current-state contract differs from retained history: %+v", current)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestApprovalRequiredSummaryNative(t *testing.T) {
	var native struct {
		Complete bool
		Cases    []struct {
			Label, Required, Status, Summary string
			Result                           struct{ Code string }
		} `json:"summary_results"`
	}
	data, err := os.ReadFile("../../../testdata/aws/codepipeline/approval_summary_requirements_complete_native.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &native); err != nil {
		t.Fatal(err)
	}
	if !native.Complete || len(native.Cases) == 0 {
		t.Fatal("native summary capture is incomplete")
	}
	for _, tc := range native.Cases {
		t.Run(tc.Label, func(t *testing.T) {
			s, ctx, pipeline, definition := kernelFixture(t, "QUEUED")
			definition.Declaration.Stages[1].Actions[0].Configuration["IsSummaryRequired"] = api.ActionConfigurationValue(tc.Required)
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				return tx.PutDefinition(definition)
			}); err != nil {
				t.Fatal(err)
			}
			execution := gateExecution(s, pipeline, "summary-execution", "QUEUED", 1)
			advanceExecution(t, s, ctx, pipeline, definition, &execution)
			pending := execution.Actions[0]
			err := s.repository.Update(ctx, func(tx Transaction) error {
				_, err := s.approve(tx, &api.PutApprovalResultInput{
					PipelineName: new(api.PipelineName(pipeline.Name)),
					StageName:    new(api.StageName(pending.StageName)),
					ActionName:   new(api.ActionName(pending.ActionName)),
					Token:        new(api.ApprovalToken(pending.ApprovalToken)),
					Result: &api.ApprovalResult{
						Status: new(api.ApprovalStatus(tc.Status)), Summary: new(api.ApprovalSummary(tc.Summary)),
					},
				})
				return err
			})
			if tc.Result.Code == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || wireError(err).Code != tc.Result.Code {
				t.Fatalf("approval result: got %v, native error %s", err, tc.Result.Code)
			}
			if err := s.repository.View(ctx, func(reader Reader) error {
				retained, err := findExecution(reader, pipeline, execution.ID)
				if err != nil {
					return err
				}
				action := retained.Actions[0]
				if tc.Result.Code != "" {
					if action.Status != "InProgress" || action.ApprovalToken != pending.ApprovalToken || action.Summary != pending.Summary {
						t.Fatalf("invalid summary consumed the pending approval: %+v", action)
					}
				} else {
					expected := "Succeeded"
					if tc.Status == "Rejected" {
						expected = "Failed"
					}
					if action.Status != expected || action.Summary != tc.Summary {
						t.Fatalf("approval decision or summary was lost: %+v", action)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
