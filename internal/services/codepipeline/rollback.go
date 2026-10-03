package codepipeline

import (
	"encoding/json"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
)

func (s *Service) rollbackStage(tx Transaction, in *api.RollbackStageInput) (*api.RollbackStageOutput, error) {
	v, err := s.pipelineFor(tx, "RollbackStage", text(in.PipelineName))
	if err != nil {
		return nil, err
	}
	d, err := findDefinition(tx, v, v.Version)
	if err != nil {
		return nil, err
	}
	stage := int32(-1)
	for i, declaration := range d.Declaration.Stages {
		if text(declaration.Name) == text(in.StageName) {
			stage = int32(i)
			break
		}
	}
	if stage < 0 {
		return nil, failure("StageNotFoundException", "Stage does not exist")
	}
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return nil, err
	}
	var target *Execution
	var sequence int64
	for i := range rows {
		sequence = max(sequence, rows[i].Sequence)
		if rows[i].ID == text(in.TargetPipelineExecutionId) {
			target = &rows[i]
		}
	}
	if target == nil {
		return nil, failure("PipelineExecutionNotFoundException", "Target pipeline execution does not exist")
	}
	if target.Version != v.Version {
		return nil, failure("PipelineExecutionOutdatedException", "Pipeline definition changed since the target execution")
	}
	if target.RollbackTargetID != "" || (target.StageIndex <= stage && target.StageStatus != "SUCCEEDED") {
		return nil, failure("UnableToRollbackStageException", "Target pipeline execution has not completed successfully in the stage")
	}
	for i := range d.Declaration.Stages[stage].Actions {
		a := latestAction(*target, stage, int32(i))
		if a == nil || a.Status != "Succeeded" {
			return nil, failure("UnableToRollbackStageException", "Target pipeline execution has not completed successfully in the stage")
		}
	}
	for _, current := range rows {
		if current.StageIndex == stage && current.StageEntered && !terminal(current.Status) {
			return nil, failure("UnableToRollbackStageException", "Cannot start rollback while the stage is in progress")
		}
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	metadata := awsctx.FromContext(tx.Context())
	detail, err := json.Marshal(struct {
		AwsUserARN string `json:"AwsUserArn"`
	}{metadata.PrincipalARN})
	if err != nil {
		return nil, err
	}
	e := Execution{Scope: v.Scope, PipelineName: v.Name, Incarnation: v.Incarnation, ID: id,
		Version: v.Version, Attempt: 1, Mode: text(d.Declaration.ExecutionMode), Status: "InProgress",
		TriggerType: "ManualRollback", TriggerDetail: string(detail), RollbackTargetID: target.ID,
		RollbackStageIndex: stage, StageIndex: stage, StageEntered: true, StageStartedAt: now,
		StartedAt: now, UpdatedAt: now, Due: now, Generation: 1, Sequence: sequence + 1,
		Variables: target.Variables, Revisions: target.Revisions,
		ParentEventID: apievents.EventID(tx.Context())}
	if e.ParentEventID == "" {
		e.ParentEventID = metadata.ParentEventID
	}
	// Reserve the stage in the admission transaction, fencing concurrent rollback
	// requests before scheduler/provider effects. Earlier/later stages stay owned
	// by their actual executions, not synthetic copied action histories.
	if err := s.saveExecution(tx, v, e); err != nil {
		return nil, err
	}
	if err := s.stageEvent(tx, v, &e, text(in.StageName), "STARTED"); err != nil {
		return nil, err
	}
	if err := tx.PutExecution(e); err != nil {
		return nil, err
	}
	return &api.RollbackStageOutput{PipelineExecutionId: new(api.PipelineExecutionId(id))}, nil
}

func executionType(e Execution) api.ExecutionType {
	if e.RollbackTargetID != "" {
		return api.ExecutionTypeROLLBACK
	}
	return api.ExecutionTypeSTANDARD
}

func rollbackMetadata(e Execution) *api.PipelineRollbackMetadata {
	if e.RollbackTargetID == "" {
		return nil
	}
	return &api.PipelineRollbackMetadata{RollbackTargetPipelineExecutionId: new(api.PipelineExecutionId(e.RollbackTargetID))}
}

// Only successful producers before the rolled-back stage supply inherited
// artifacts. New outputs from the rollback stage always outrank these references.
func rollbackArtifact(target Execution, stage int32, name string) (Artifact, bool) {
	for i := len(target.Actions) - 1; i >= 0; i-- {
		a := &target.Actions[i]
		if a.StageIndex >= stage || a.Status != "Succeeded" {
			continue
		}
		for _, artifact := range a.OutputArtifacts {
			if artifact.Name == name {
				return artifact, true
			}
		}
	}
	return Artifact{}, false
}
