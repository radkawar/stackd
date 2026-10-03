package codepipeline

import (
	"context"
	"errors"
	"sync"
	"testing"

	api "stackd/internal/awsapi/codepipeline"
)

func TestRollbackReservesStageAndDoesNotAdvanceDownstream(t *testing.T) {
	for _, mode := range []string{"SUPERSEDED", "QUEUED", "PARALLEL"} {
		t.Run(mode, func(t *testing.T) {
			s, ctx, v, d := kernelFixture(t, mode)
			next := d.Declaration.Stages[1]
			next.Name = new(api.StageName("Downstream"))
			d.Declaration.Stages = append(d.Declaration.Stages, next)
			target := gateExecution(s, v, "target", mode, 1)
			target.Status = "Succeeded"
			target.StageIndex = 3
			target.Due = target.Due.AddDate(-1, 0, 0)
			target.Actions = []ActionExecution{{ID: "source", StageName: "Source", ActionName: "Source", StageIndex: 0, Status: "Succeeded", StartedAt: s.clock.Now()}, {ID: "approval", StageName: "Gate", ActionName: "Review", StageIndex: 1, Status: "Succeeded", StartedAt: s.clock.Now()}, {ID: "downstream", StageName: "Downstream", ActionName: "Review", StageIndex: 2, Status: "Succeeded", StartedAt: s.clock.Now()}}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutDefinition(d); err != nil {
					return err
				}
				return tx.PutExecution(target)
			}); err != nil {
				t.Fatal(err)
			}
			input := &api.RollbackStageInput{PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")), TargetPipelineExecutionId: new(api.PipelineExecutionId(target.ID))}
			type result struct {
				id  string
				err error
			}
			results := make(chan result, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() {
					var id string
					err := s.repository.Update(ctx, func(tx Transaction) error {
						out, err := s.rollbackStage(tx, input)
						if err == nil {
							id = text(out.PipelineExecutionId)
						}
						return err
					})
					results <- result{id, err}
				})
			}
			wg.Wait()
			close(results)
			var rollback Execution
			accepted, denied := 0, 0
			for result := range results {
				if result.err != nil {
					if wireError(result.err).Code != "UnableToRollbackStageException" {
						t.Fatal(result.err)
					}
					denied++
					continue
				}
				accepted++
				if err := s.repository.View(ctx, func(r Reader) error { var err error; rollback, err = findExecution(r, v, result.id); return err }); err != nil {
					t.Fatal(err)
				}
			}
			if accepted != 1 || denied != 1 {
				t.Fatalf("concurrent rollback admitted %d rejected %d", accepted, denied)
			}
			advanceExecution(t, s, ctx, v, d, &rollback)
			if len(rollback.Actions) != 1 || rollback.Actions[0].StageName != "Gate" {
				t.Fatalf("rollback actions: %+v", rollback.Actions)
			}
			rollback.Actions[0].Status = "Succeeded"
			advanceExecution(t, s, ctx, v, d, &rollback)
			if rollback.Status != "Succeeded" || rollback.StageIndex != 1 || len(rollback.Actions) != 1 {
				t.Fatalf("rollback progressed downstream: %+v", rollback)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				state, err := s.getState(tx, &api.GetPipelineStateInput{Name: new(api.PipelineName(v.Name))})
				if err != nil {
					return err
				}
				if text(state.StageStates[0].LatestExecution.PipelineExecutionId) != target.ID || text(state.StageStates[1].LatestExecution.PipelineExecutionId) != rollback.ID || text(state.StageStates[2].LatestExecution.PipelineExecutionId) != target.ID {
					t.Fatalf("rollback stole another stage: %+v", state)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type rollbackEventFailure struct{ observedEvents }

func (*rollbackEventFailure) StageStateChanged(context.Context, Pipeline, Execution, string, string) error {
	return errors.New("stage event commit failed")
}

func TestRollbackEventFailureLeavesNoExecutionOrStageReservation(t *testing.T) {
	s, ctx, v, _ := kernelFixture(t, "SUPERSEDED")
	target := gateExecution(s, v, "target", "SUPERSEDED", 1)
	target.Status = "Succeeded"
	target.StageIndex = 2
	target.Actions = []ActionExecution{{ID: "approval", StageName: "Gate", ActionName: "Review", StageIndex: 1, Status: "Succeeded", StartedAt: s.clock.Now()}}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutExecution(target) }); err != nil {
		t.Fatal(err)
	}
	s.events = &rollbackEventFailure{}
	input := &api.RollbackStageInput{PipelineName: new(api.PipelineName(v.Name)), StageName: new(api.StageName("Gate")), TargetPipelineExecutionId: new(api.PipelineExecutionId(target.ID))}
	err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.rollbackStage(tx, input); return err })
	if err == nil {
		t.Fatal("event failure did not reject rollback")
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.Executions(v.Scope, v.Incarnation)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].ID != target.ID {
			t.Fatalf("failed rollback leaked execution: %+v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.events = nil
	if err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.rollbackStage(tx, input); return err }); err != nil {
		t.Fatalf("failed admission left stage locked: %v", err)
	}
}
