package codepipeline

import (
	"context"
	"fmt"
	"slices"
	"stackd/clock"
	api "stackd/internal/awsapi/codepipeline"
	"testing"
	"time"
)

type observedStageEvent struct {
	stage, state string
	attempt      int32
}
type observedEvents struct {
	stages    []observedStageEvent
	pipelines []string
}

func (o *observedEvents) PipelineStateChanged(_ context.Context, _ Pipeline, e Execution) error {
	o.pipelines = append(o.pipelines, fmt.Sprintf("%s/%d", e.Status, e.Attempt))
	return nil
}
func (o *observedEvents) StageStateChanged(_ context.Context, _ Pipeline, e Execution, stage, state string) error {
	o.stages = append(o.stages, observedStageEvent{stage, state, e.Attempt})
	return nil
}
func (*observedEvents) ActionStateChanged(context.Context, Pipeline, Execution, ActionExecution, api.ActionDeclaration) error {
	return nil
}
func TestExplicitStageEventsAndExecutionAttemptAcrossStages(t *testing.T) {
	s, ctx, v, d := kernelFixture(t, "QUEUED")
	events := &observedEvents{}
	s.events = events
	next := d.Declaration.Stages[1]
	next.Name = new(api.StageName("Production"))
	d.Declaration.Stages = append(d.Declaration.Stages, next)
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutDefinition(d) }); err != nil {
		t.Fatal(err)
	}
	e := gateExecution(s, v, "execution", "QUEUED", 1)
	reload := func() {
		t.Helper()
		if err := s.repository.View(ctx, func(r Reader) error { var err error; e, err = findExecution(r, v, e.ID); return err }); err != nil {
			t.Fatal(err)
		}
	}
	retry := func(stage string) {
		t.Helper()
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.retryStage(tx, &api.RetryStageExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), StageName: new(api.StageName(stage)), RetryMode: new(api.StageRetryMode("FAILED_ACTIONS"))})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		reload()
	}
	advanceExecution(t, s, ctx, v, d, &e)
	stageStart := e.StageStartedAt
	if e.Attempt != 1 || !e.StageLastRetryAt.IsZero() || !e.LastRetryAt.IsZero() {
		t.Fatalf("initial stage unexpectedly has retry state: %+v", e)
	}
	latestAction(e, 1, 0).Status = "Failed"
	advanceExecution(t, s, ctx, v, d, &e)
	if err := s.clock.(*clock.Manual).Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	retry("Gate")
	if e.Attempt != 2 || !e.StageStartedAt.Equal(stageStart) || !e.LastRetryAt.Equal(s.clock.Now()) || !e.StageLastRetryAt.Equal(e.LastRetryAt) {
		t.Fatalf("retry reset stage start or lost accepted retry time: %+v", e)
	}
	firstRetryTime := e.LastRetryAt
	advanceExecution(t, s, ctx, v, d, &e)
	latestAction(e, 1, 0).Status = "Succeeded"
	advanceExecution(t, s, ctx, v, d, &e)
	advanceExecution(t, s, ctx, v, d, &e)
	secondStageStart := e.StageStartedAt
	if e.Attempt != 2 || !e.StageLastRetryAt.IsZero() || !e.LastRetryAt.Equal(firstRetryTime) {
		t.Fatalf("advancing reset the global attempt or leaked the previous stage retry time: %+v", e)
	}
	latestAction(e, 2, 0).Status = "Failed"
	advanceExecution(t, s, ctx, v, d, &e)
	if err := s.clock.(*clock.Manual).Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	retry("Production")
	if e.Attempt != 3 {
		t.Fatalf("execution attempts across stages: %d", e.Attempt)
	}
	if !e.StageStartedAt.Equal(secondStageStart) || !e.LastRetryAt.Equal(s.clock.Now()) || !e.StageLastRetryAt.Equal(e.LastRetryAt) {
		t.Fatalf("later-stage retry lost its own start/retry timestamp: %+v", e)
	}
	maxAction := int32(0)
	for _, a := range e.Actions {
		maxAction = max(maxAction, a.Attempt)
	}
	if maxAction != 2 {
		t.Fatalf("expected per-action attempts to differ from execution attempt: %d", maxAction)
	}
	want := []observedStageEvent{{"Gate", "STARTED", 1}, {"Gate", "FAILED", 1}, {"Gate", "RESUMED", 2}, {"Gate", "SUCCEEDED", 2}, {"Production", "STARTED", 2}, {"Production", "FAILED", 2}, {"Production", "RESUMED", 3}}
	if !slices.Equal(events.stages, want) {
		t.Fatalf("stage transition events: got %+v want %+v", events.stages, want)
	}
	if !slices.Equal(events.pipelines, []string{"InProgress/2", "InProgress/3"}) {
		t.Fatalf("retry pipeline transitions: %+v", events.pipelines)
	}
}
func TestCompletedOutboundHoldEmitsStageSuccessOnce(t *testing.T) {
	s, ctx, v, d := kernelFixture(t, "QUEUED")
	events := &observedEvents{}
	s.events = events
	v.Transitions = []Transition{{Stage: "Gate", Type: "Outbound", Disabled: true}}
	e := gateExecution(s, v, "execution", "QUEUED", 1)
	advanceExecution(t, s, ctx, v, d, &e)
	e.Actions[0].Status = "Succeeded"
	advanceExecution(t, s, ctx, v, d, &e)
	advanceExecution(t, s, ctx, v, d, &e)
	want := []observedStageEvent{{"Gate", "STARTED", 1}, {"Gate", "SUCCEEDED", 1}}
	if !slices.Equal(events.stages, want) || e.StageStatus != "SUCCEEDED" || e.Status != "InProgress" {
		t.Fatalf("completed outbound hold repeated/misreported completion: %+v %+v", events.stages, e)
	}
	v.Transitions = nil
	advanceExecution(t, s, ctx, v, d, &e)
	if e.Status != "Succeeded" || !slices.Equal(events.stages, want) {
		t.Fatal("releasing completed hold emitted duplicate stage success")
	}
}
func TestAbandonEmitsStoppingAndStoppedStageTransitions(t *testing.T) {
	s, ctx, v, d := kernelFixture(t, "QUEUED")
	events := &observedEvents{}
	s.events = events
	e := gateExecution(s, v, "execution", "QUEUED", 1)
	advanceExecution(t, s, ctx, v, d, &e)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{PipelineName: new(api.PipelineName(v.Name)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Abandon: new(api.Boolean(true))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := []observedStageEvent{{"Gate", "STARTED", 1}, {"Gate", "STOPPING", 1}, {"Gate", "STOPPED", 1}}
	if !slices.Equal(events.stages, want) || !slices.Equal(events.pipelines, []string{"Stopping/1", "Stopped/1"}) {
		t.Fatalf("abandon transitions: stages=%+v pipeline=%+v", events.stages, events.pipelines)
	}
}
func TestDrainedStageStopEvents(t *testing.T) {
	s, ctx, v, d := kernelFixture(t, "QUEUED")
	events := &observedEvents{}
	s.events = events
	e := gateExecution(s, v, "execution", "QUEUED", 1)
	advanceExecution(t, s, ctx, v, d, &e)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.stopPipeline(tx, &api.StopPipelineExecutionInput{
			PipelineName:        new(api.PipelineName(v.Name)),
			PipelineExecutionId: new(api.PipelineExecutionId(e.ID)),
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
	if terminal(e.Status) {
		t.Fatal("stage terminated while its admitted approval was active")
	}
	e.Actions[0].Status = "Succeeded"
	advanceExecution(t, s, ctx, v, d, &e)
	want := []observedStageEvent{{"Gate", "STARTED", 1}, {"Gate", "STOPPING", 1}, {"Gate", "STOPPED", 1}}
	if !slices.Equal(events.stages, want) || e.Status != "Stopped" {
		t.Fatalf("drained stage transitions: %+v status=%s", events.stages, e.Status)
	}
}
