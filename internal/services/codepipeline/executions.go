package codepipeline

import (
	"slices"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
	"strings"
	"time"
)

func registerExecutions(s *Service) {
	register(s, "StartPipelineExecution", s.startPipeline)
	register(s, "StopPipelineExecution", s.stopPipeline)
	register(s, "RetryStageExecution", s.retryStage)
	register(s, "RollbackStage", s.rollbackStage)
	register(s, "PutApprovalResult", s.approve)
	register(s, "EnableStageTransition", func(tx Transaction, in *api.EnableStageTransitionInput) (*struct{}, error) {
		return s.transition(tx, "EnableStageTransition", text(in.PipelineName), text(in.StageName), text(in.TransitionType), "")
	})
	register(s, "DisableStageTransition", func(tx Transaction, in *api.DisableStageTransitionInput) (*struct{}, error) {
		return s.transition(tx, "DisableStageTransition", text(in.PipelineName), text(in.StageName), text(in.TransitionType), text(in.Reason))
	})
}
func (s *Service) startPipeline(tx Transaction, in *api.StartPipelineExecutionInput) (*api.StartPipelineExecutionOutput, error) {
	v, err := s.pipelineFor(tx, "StartPipelineExecution", text(in.Name))
	if err != nil {
		return nil, err
	}
	d, err := findDefinition(tx, v, v.Version)
	if err != nil {
		return nil, err
	}
	id, err := s.startExecution(tx, v, d, text(in.ClientRequestToken), in.SourceRevisions, in.Variables, "StartPipelineExecution")
	if err != nil {
		return nil, err
	}
	return &api.StartPipelineExecutionOutput{PipelineExecutionId: new(api.PipelineExecutionId(id))}, nil
}
func (s *Service) startExecution(tx Transaction, v Pipeline, d Definition, token string, overrides api.SourceRevisionOverrideList, variables api.PipelineVariableList, trigger string) (string, error) {
	seen := map[string]bool{}
	for _, o := range overrides {
		key := text(o.ActionName) + "/" + text(o.RevisionType)
		if seen[key] {
			return "", failure("ValidationException", "Duplicate source revision override")
		}
		seen[key] = true
		found := false
		for _, a := range d.Declaration.Stages[0].Actions {
			if text(a.Name) != text(o.ActionName) {
				continue
			}
			found = true
			kind := text(o.RevisionType)
			if kind != "S3_OBJECT_VERSION_ID" && kind != "S3_OBJECT_KEY" {
				return "", failure("ValidationException", "S3 source requires an S3 source revision override")
			}
			if kind == "S3_OBJECT_KEY" && a.Configuration["AllowOverrideForS3ObjectKey"] != "true" {
				return "", failure("ValidationException", "S3 object-key overrides are disabled")
			}
			if text(o.RevisionValue) == "" {
				return "", failure("ValidationException", "Source revision value is required")
			}
		}
		if !found {
			return "", failure("ValidationException", "Source action does not exist: "+text(o.ActionName))
		}
	}
	// Native validates duplicate variable names before replaying a retained token,
	// but the token alone owns execution identity regardless of override values.
	values, err := pipelineVariableOverrides(variables)
	if err != nil {
		return "", err
	}
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return "", err
	}
	var sequence int64
	for _, e := range rows {
		sequence = max(sequence, e.Sequence)
		if token != "" && e.ClientToken == token {
			return e.ID, nil
		}
	}
	resolved, missing := bindPipelineVariables(d.Declaration.Variables, values)
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := s.clock.Now().UTC()
	e := Execution{Scope: v.Scope, PipelineName: v.Name, Incarnation: v.Incarnation, ID: id, ClientToken: token, Version: v.Version, Mode: text(d.Declaration.ExecutionMode), Status: "InProgress", TriggerType: trigger, TriggerDetail: awsctx.FromContext(tx.Context()).PrincipalARN, StartedAt: now, UpdatedAt: now, Due: now, Generation: 1, Sequence: sequence + 1, SourceOverrides: overrides, ParentEventID: apievents.EventID(tx.Context())}
	e.Attempt = 1
	e.Variables = resolved
	if e.ParentEventID == "" {
		e.ParentEventID = awsctx.FromContext(tx.Context()).ParentEventID
	}
	origin := awsctx.FromContext(tx.Context())
	if trigger == "StartPipelineExecution" && (origin.InvokedBy == "events.amazonaws.com" || origin.InvokedBy == "events.amazonaws.com.cn") {
		e.TriggerType = "CloudWatchEvent"
		e.TriggerDetail = origin.ServicePrincipal.SourceARN
	}
	if trigger == "PollForSourceChanges" && len(overrides) > 0 {
		e.TriggerDetail = text(overrides[0].ActionName)
	}
	if err = s.saveExecution(tx, v, e); err != nil {
		return "", err
	}
	if len(missing) > 0 {
		finish(&e, "Failed", "Values for required variables haven't been provided: "+strings.Join(missing, ","), now)
		if err = s.saveExecution(tx, v, e); err != nil {
			return "", err
		}
	}
	return id, nil
}
func (s *Service) stopPipeline(tx Transaction, in *api.StopPipelineExecutionInput) (*api.StopPipelineExecutionOutput, error) {
	v, err := s.pipelineFor(tx, "StopPipelineExecution", text(in.PipelineName))
	if err != nil {
		return nil, err
	}
	e, err := findExecution(tx, v, text(in.PipelineExecutionId))
	if err != nil {
		return nil, err
	}
	if terminal(e.Status) {
		return nil, failure("PipelineExecutionNotStoppableException", "Execution is not running")
	}
	abandon := bool(value(in.Abandon))
	if e.Status == "Stopping" && !abandon {
		return nil, failure("DuplicatedStopRequestException", "Execution is already stopping")
	}
	wasStopping := e.Status == "Stopping"
	now := s.clock.Now().UTC()
	e.StopReason = text(in.Reason)
	e.Status = "Stopping"
	e.Generation++
	e.UpdatedAt = now
	e.Due = now
	stageName := ""
	d, err := findDefinition(tx, v, e.Version)
	if err != nil {
		return nil, err
	}
	if e.StageEntered {
		if e.StageIndex < int32(len(d.Declaration.Stages)) {
			stageName = text(d.Declaration.Stages[e.StageIndex].Name)
		}
		if err = s.stageEvent(tx, v, &e, stageName, "STOPPING"); err != nil {
			return nil, err
		}
	}
	if abandon && !wasStopping && s.events != nil {
		if err = s.events.PipelineStateChanged(tx.Context(), v, e); err != nil {
			return nil, err
		}
	}
	if abandon {
		for i := range e.Actions {
			a := &e.Actions[i]
			if a.Status == "InProgress" {
				a.Status = "Abandoned"
				a.UpdatedAt = now
				if a.ApprovalToken != "" {
					a.Summary = "The approval action has been canceled."
				}
				if err = s.actionEvent(tx, v, e, *a, d.Declaration.Stages[a.StageIndex].Actions[a.ActionIndex]); err != nil {
					return nil, err
				}
			}
		}
		finish(&e, "Stopped", e.StopReason, now)
		if err = s.stageEvent(tx, v, &e, stageName, "STOPPED"); err != nil {
			return nil, err
		}
	}
	if err = s.saveExecution(tx, v, e); err != nil {
		return nil, err
	}
	if abandon {
		if err = s.wakeOtherExecutions(tx, v, e.ID); err != nil {
			return nil, err
		}
	}
	return &api.StopPipelineExecutionOutput{PipelineExecutionId: new(api.PipelineExecutionId(e.ID))}, nil
}
func (s *Service) retryStage(tx Transaction, in *api.RetryStageExecutionInput) (*api.RetryStageExecutionOutput, error) {
	v, err := s.pipelineFor(tx, "RetryStageExecution", text(in.PipelineName))
	if err != nil {
		return nil, err
	}
	e, err := findExecution(tx, v, text(in.PipelineExecutionId))
	if err != nil {
		return nil, err
	}
	if e.Version != v.Version {
		return nil, failure("StageNotRetryableException", "Pipeline definition changed")
	}
	d, err := findDefinition(tx, v, e.Version)
	if err != nil {
		return nil, err
	}
	index := -1
	for i, st := range d.Declaration.Stages {
		if text(st.Name) == text(in.StageName) {
			index = i
		}
	}
	if index < 0 {
		return nil, failure("StageNotFoundException", "Stage does not exist")
	}
	if e.Status != "Failed" && e.Status != "Stopped" {
		return nil, failure("StageNotRetryableException", "Execution is not failed or stopped")
	}
	if e.StageIndex != int32(index) || !e.StageEntered {
		return nil, failure("StageNotRetryableException", "Stage has no retryable action executions")
	}
	mode := text(in.RetryMode)
	if mode != "FAILED_ACTIONS" && mode != "ALL_ACTIONS" {
		return nil, failure("ValidationException", "Invalid retry mode")
	}
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return nil, err
	}
	for _, other := range rows {
		if other.Sequence <= e.Sequence {
			continue
		}
		for _, a := range other.Actions {
			if a.StageIndex == int32(index) && !a.StartedAt.IsZero() {
				return nil, failure("NotLatestPipelineExecutionException", "A newer execution entered the stage")
			}
		}
	}
	reset := 0
	for j := range d.Declaration.Stages[index].Actions {
		a := latestAction(e, int32(index), int32(j))
		if a == nil {
			continue
		}
		if mode == "FAILED_ACTIONS" && a.Status == "Succeeded" {
			continue
		}
		if a.Status == "InProgress" {
			return nil, failure("StageNotRetryableException", "Action is still running")
		}
		id, err := newID()
		if err != nil {
			return nil, err
		}
		e.Actions = append(e.Actions, ActionExecution{ID: id, StageName: a.StageName, ActionName: a.ActionName, StageIndex: a.StageIndex, ActionIndex: a.ActionIndex, Attempt: a.Attempt + 1, Status: "Pending"})
		reset++
	}
	if reset == 0 {
		return nil, failure("StageNotRetryableException", "Stage has no actions to retry")
	}
	e.Status = "InProgress"
	e.Summary = ""
	e.StopReason = ""
	e.UpdatedDefinition = false
	e.UpdatedAt = s.clock.Now().UTC()
	e.Due = e.UpdatedAt
	e.Generation++
	e.Attempt++
	e.LastRetryAt = e.UpdatedAt
	e.StageLastRetryAt = e.UpdatedAt
	if err = s.stageEvent(tx, v, &e, text(in.StageName), "RESUMED"); err != nil {
		return nil, err
	}
	if err = s.saveExecution(tx, v, e); err != nil {
		return nil, err
	}
	return &api.RetryStageExecutionOutput{PipelineExecutionId: new(api.PipelineExecutionId(e.ID))}, nil
}
func (s *Service) transition(tx Transaction, operation, name, stage, kind, reason string) (*struct{}, error) {
	v, err := s.pipelineFor(tx, operation, name)
	if err != nil {
		return nil, err
	}
	if kind != "Inbound" && kind != "Outbound" {
		return nil, failure("ValidationException", "Invalid transition type")
	}
	if operation == "DisableStageTransition" && reason == "" {
		return nil, failure("ValidationException", "A disabled transition requires a reason")
	}
	d, err := findDefinition(tx, v, v.Version)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(d.Declaration.Stages, func(st api.StageDeclaration) bool { return text(st.Name) == stage }) {
		return nil, failure("StageNotFoundException", "Stage does not exist")
	}
	t := Transition{Stage: stage, Type: kind, Disabled: operation == "DisableStageTransition", Reason: reason, ChangedAt: s.clock.Now().UTC(), ChangedBy: awsctx.FromContext(tx.Context()).PrincipalARN}
	found := false
	for i := range v.Transitions {
		if v.Transitions[i].Stage == stage && v.Transitions[i].Type == kind {
			v.Transitions[i] = t
			found = true
		}
	}
	if !found {
		v.Transitions = append(v.Transitions, t)
	}
	if err = tx.PutPipeline(v); err != nil {
		return nil, err
	}
	if err = s.wakeExecutions(tx, v); err != nil {
		return nil, err
	}
	return &struct{}{}, nil
}
func (s *Service) wakeExecutions(tx Transaction, p Pipeline) error {
	rows, err := tx.Executions(p.Scope, p.Incarnation)
	if err != nil {
		return err
	}
	for _, e := range rows {
		if terminal(e.Status) {
			continue
		}
		e.Due = s.clock.Now().UTC()
		e.Generation++
		if err = tx.PutExecution(e); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) approve(tx Transaction, in *api.PutApprovalResultInput) (*api.PutApprovalResultOutput, error) {
	v, err := s.pipelineFor(tx, "PutApprovalResult", text(in.PipelineName))
	if err != nil {
		return nil, err
	}
	if in.Result == nil || (text(in.Result.Status) != "Approved" && text(in.Result.Status) != "Rejected") {
		return nil, failure("ValidationException", "Approval result must be Approved or Rejected")
	}
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	for _, e := range rows {
		for i := range e.Actions {
			a := &e.Actions[i]
			if a.StageName != text(in.StageName) || a.ActionName != text(in.ActionName) || a.ApprovalToken == "" || a.ApprovalToken != text(in.Token) {
				continue
			}
			if e.UpdatedDefinition || a.Status == "Abandoned" {
				return nil, failure("InvalidApprovalTokenException", "The pipeline "+v.Name+" has been updated, and the approval request you responded to is now out of date.")
			}
			if a.Status != "InProgress" {
				return nil, failure("ApprovalAlreadyCompletedException", "Approval already completed")
			}
			d, err := findDefinition(tx, v, e.Version)
			if err != nil {
				return nil, err
			}
			decl := d.Declaration.Stages[a.StageIndex].Actions[a.ActionIndex]
			if !now.Before(approvalDeadline(*a, decl)) {
				return nil, failure("InvalidApprovalTokenException", "Approval token expired")
			}
			if a.ResolvedConfiguration["IsSummaryRequired"] == "true" && strings.TrimSpace(text(in.Result.Summary)) == "" {
				return nil, failure("InvalidApprovalTokenException", "Action '"+a.ActionName+"' in stage '"+a.StageName+"' requires a summary. Provide a summary in the approval result and try again.")
			}
			a.Status = "Succeeded"
			if text(in.Result.Status) == "Rejected" {
				a.Status = "Failed"
			}
			a.Summary = text(in.Result.Summary)
			a.UpdatedAt = now
			a.UpdatedBy = awsctx.FromContext(tx.Context()).PrincipalARN
			a.ExternalExecutionID = a.ID
			e.Due = now
			e.Generation++
			e.UpdatedAt = now
			if err = s.actionEvent(tx, v, e, *a, decl); err != nil {
				return nil, err
			}
			if err = tx.PutExecution(e); err != nil {
				return nil, err
			}
			return &api.PutApprovalResultOutput{ApprovedAt: &now}, nil
		}
	}
	return nil, failure("InvalidApprovalTokenException", "Approval token is not valid")
}
func latestAction(e Execution, stage, index int32) *ActionExecution {
	for i := len(e.Actions) - 1; i >= 0; i-- {
		if e.Actions[i].StageIndex == stage && e.Actions[i].ActionIndex == index {
			return &e.Actions[i]
		}
	}
	return nil
}
func approvalDeadline(a ActionExecution, d api.ActionDeclaration) time.Time {
	duration := 7 * 24 * time.Hour
	if d.TimeoutInMinutes != nil {
		duration = time.Duration(*d.TimeoutInMinutes) * time.Minute
	}
	return a.StartedAt.Add(duration)
}
