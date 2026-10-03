package codepipeline

import (
	"cmp"
	"net/url"
	"slices"
	api "stackd/internal/awsapi/codepipeline"
	"time"
)

func registerHistory(s *Service) {
	register(s, "GetPipelineExecution", s.getExecution)
	register(s, "ListPipelineExecutions", s.listExecutions)
	register(s, "ListActionExecutions", s.listActions)
	register(s, "GetPipelineState", s.getState)
}
func (s *Service) getExecution(tx Transaction, in *api.GetPipelineExecutionInput) (*api.GetPipelineExecutionOutput, error) {
	v, err := s.pipelineFor(tx, "GetPipelineExecution", text(in.PipelineName))
	if err != nil {
		return nil, err
	}
	e, err := findExecution(tx, v, text(in.PipelineExecutionId))
	if err != nil {
		return nil, err
	}
	out := &api.PipelineExecution{PipelineName: new(api.PipelineName(e.PipelineName)), PipelineVersion: new(api.PipelineVersion(e.Version)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Status: new(api.PipelineExecutionStatus(e.Status)), ExecutionMode: new(api.ExecutionMode(e.Mode)), ExecutionType: new(executionType(e)), Trigger: executionTrigger(e), ArtifactRevisions: api.ArtifactRevisionList{}, RollbackMetadata: rollbackMetadata(e)}
	out.Variables = e.Variables
	if e.Summary != "" {
		out.StatusSummary = new(api.PipelineExecutionStatusSummary(e.Summary))
	}
	for _, r := range e.Revisions {
		out.ArtifactRevisions = append(out.ArtifactRevisions, api.ArtifactRevision{Name: new(api.ArtifactName(r.ArtifactName)), RevisionId: new(api.Revision(r.RevisionID)), RevisionChangeIdentifier: optional[api.RevisionChangeIdentifier](r.ChangeID), RevisionSummary: optional[api.RevisionSummary](r.Summary), RevisionUrl: optional[api.Url](r.URL), Created: optionalTimestamp(r.CreatedAt)})
	}
	return &api.GetPipelineExecutionOutput{PipelineExecution: out}, nil
}
func executionTrigger(e Execution) *api.ExecutionTrigger {
	return &api.ExecutionTrigger{TriggerType: new(api.TriggerType(e.TriggerType)), TriggerDetail: optional[api.TriggerDetail](e.TriggerDetail)}
}
func optional[T ~string](s string) *T {
	if s == "" {
		return nil
	}
	return new(T(s))
}

func optionalTimestamp(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func (s *Service) listExecutions(tx Transaction, in *api.ListPipelineExecutionsInput) (*api.ListPipelineExecutionsOutput, error) {
	v, err := s.pipelineFor(tx, "ListPipelineExecutions", text(in.PipelineName))
	if err != nil {
		return nil, err
	}
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return nil, err
	}
	filter := ""
	if in.Filter != nil && in.Filter.SucceededInStage != nil {
		filter = text(in.Filter.SucceededInStage.StageName)
		rows = slices.DeleteFunc(rows, func(e Execution) bool {
			d, ok, _ := tx.Definition(e.Scope, e.Incarnation, e.Version)
			if !ok {
				return true
			}
			for i, st := range d.Declaration.Stages {
				if text(st.Name) != filter {
					continue
				}
				for j := range st.Actions {
					a := latestAction(e, int32(i), int32(j))
					if a == nil || a.Status != "Succeeded" {
						return true
					}
				}
				return false
			}
			return true
		})
	}
	slices.Reverse(rows)
	start, end, next, err := page(v.Scope, "executions:"+v.Incarnation+":"+filter, text(in.NextToken), int(value(in.MaxResults)), len(rows))
	if err != nil {
		return nil, err
	}
	out := &api.ListPipelineExecutionsOutput{NextToken: next, PipelineExecutionSummaries: api.PipelineExecutionSummaryList{}}
	for _, e := range rows[start:end] {
		row := api.PipelineExecutionSummary{PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Status: new(api.PipelineExecutionStatus(e.Status)), StatusSummary: optional[api.PipelineExecutionStatusSummary](e.Summary), StartTime: &e.StartedAt, LastUpdateTime: &e.UpdatedAt, ExecutionMode: new(api.ExecutionMode(e.Mode)), ExecutionType: new(executionType(e)), Trigger: executionTrigger(e), SourceRevisions: api.SourceRevisionList{}, RollbackMetadata: rollbackMetadata(e)}
		if e.StopReason != "" {
			row.StopTrigger = &api.StopExecutionTrigger{Reason: new(api.StopPipelineExecutionReason(e.StopReason))}
		}
		for _, r := range e.Revisions {
			row.SourceRevisions = append(row.SourceRevisions, api.SourceRevision{ActionName: new(api.ActionName(r.ActionName)), RevisionId: new(api.Revision(r.RevisionID)), RevisionSummary: optional[api.RevisionSummary](r.Summary), RevisionUrl: optional[api.Url](r.URL)})
		}
		out.PipelineExecutionSummaries = append(out.PipelineExecutionSummaries, row)
	}
	return out, nil
}

// ArtifactDetails exposes the retained S3 locations in the generated API shape
// shared by action history and state-change events.
func ArtifactDetails(artifacts []Artifact) api.ArtifactDetailList {
	out := make(api.ArtifactDetailList, len(artifacts))
	for i, a := range artifacts {
		out[i] = api.ArtifactDetail{Name: new(api.ArtifactName(a.Name)), S3location: &api.S3Location{Bucket: new(api.S3Bucket(a.Bucket)), Key: new(api.S3Key(a.Key))}}
	}
	return out
}
func actionError(a ActionExecution) *api.ErrorDetails {
	if a.ErrorCode == "" && a.ErrorMessage == "" {
		return nil
	}
	return &api.ErrorDetails{Code: optional[api.Code](a.ErrorCode), Message: optional[api.Message](a.ErrorMessage)}
}

func approvalNotificationFailed(a ActionExecution) bool {
	return a.ApprovalToken != "" && a.ResolvedConfiguration["NotificationArn"] != "" &&
		a.Status == "Failed" && a.ApprovalNotificationID == "" && a.ErrorCode != "" && a.ErrorCode != "ApprovalTimedOut"
}
func actionDetail(e Execution, a ActionExecution, d Definition) api.ActionExecutionDetail {
	decl := d.Declaration.Stages[a.StageIndex].Actions[a.ActionIndex]
	resolved := api.ResolvedActionConfigurationMap{}
	for k, v := range a.ResolvedConfiguration {
		resolved[api.String(k)] = api.String(v)
	}
	role := decl.RoleArn
	if role == nil {
		role = d.Declaration.RoleArn
	}
	region := decl.Region
	if region == nil {
		region = new(api.AWSRegionName(e.Region))
	}
	details := actionError(a)
	if details != nil && (approvalNotificationFailed(a) || text(decl.ActionTypeId.Provider) == "Lambda") {
		// These providers expose failure text in the history summary instead.
		details.Message = nil
	}
	return api.ActionExecutionDetail{
		ActionExecutionId: new(api.ActionExecutionId(a.ID)), ActionName: new(api.ActionName(a.ActionName)), StageName: new(api.StageName(a.StageName)), PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), PipelineVersion: new(api.PipelineVersion(e.Version)), Status: new(api.ActionExecutionStatus(a.Status)), StartTime: &a.StartedAt, LastUpdateTime: &a.UpdatedAt,
		UpdatedBy: optional[api.LastUpdatedBy](a.UpdatedBy),
		Input:     &api.ActionExecutionInput{ActionTypeId: decl.ActionTypeId, Configuration: decl.Configuration, ResolvedConfiguration: resolved, RoleArn: role, Region: region, Namespace: decl.Namespace, InputArtifacts: ArtifactDetails(a.InputArtifacts)},
		Output:    &api.ActionExecutionOutput{OutputVariables: a.OutputVariables, OutputArtifacts: ArtifactDetails(a.OutputArtifacts), ExecutionResult: &api.ActionExecutionResult{ExternalExecutionId: optional[api.ExternalExecutionId](a.ExternalExecutionID), ExternalExecutionUrl: optional[api.Url](a.ExternalExecutionURL), ExternalExecutionSummary: optional[api.ExternalExecutionSummary](a.Summary), ErrorDetails: details}},
	}
}

func (s *Service) listActions(tx Transaction, in *api.ListActionExecutionsInput) (*api.ListActionExecutionsOutput, error) {
	v, err := s.pipelineFor(tx, "ListActionExecutions", text(in.PipelineName))
	if err != nil {
		return nil, err
	}
	filter, latestExecution := "", ""
	latestOnly := false
	if in.Filter != nil {
		filter = text(in.Filter.PipelineExecutionId)
		if latest := in.Filter.LatestInPipelineExecution; latest != nil {
			latestExecution = text(latest.PipelineExecutionId)
			latestOnly = text(latest.StartTimeRange) == "Latest"
			if filter == "" {
				filter = latestExecution
			}
		}
	}
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return nil, err
	}
	if filter != "" {
		index := slices.IndexFunc(rows, func(e Execution) bool { return e.ID == filter })
		if index < 0 {
			return nil, failure("PipelineExecutionNotFoundException", "Pipeline execution not found: "+filter)
		}
		rows = rows[index : index+1]
	}
	query := "actions:" + v.Incarnation + ":" + filter
	if latestOnly {
		query += ":latest"
	}
	if latestExecution != "" && latestExecution != filter {
		// AWS validates the top-level ID when supplied, then intersects the
		// nested selection without requiring that second execution to exist.
		rows = nil
		query += ":" + latestExecution
	}
	details := api.ActionExecutionDetailList{}
	for _, e := range rows {
		d, err := findDefinition(tx, v, e.Version)
		if err != nil {
			return nil, err
		}
		var seen map[[2]int32]struct{}
		if latestOnly {
			seen = make(map[[2]int32]struct{})
		}
		// All includes historical retries. Latest selects the newest started
		// attempt for each action, not only actions after the pipeline's retry.
		for i := len(e.Actions) - 1; i >= 0; i-- {
			a := &e.Actions[i]
			if a.StartedAt.IsZero() {
				continue
			}
			if latestOnly {
				key := [2]int32{a.StageIndex, a.ActionIndex}
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
			}
			details = append(details, actionDetail(e, *a, d))
		}
	}
	slices.SortStableFunc(details, func(a, b api.ActionExecutionDetail) int {
		if n := b.StartTime.Compare(*a.StartTime); n != 0 {
			return n
		}
		return cmp.Compare(text(a.ActionExecutionId), text(b.ActionExecutionId))
	})
	start, end, next, err := page(v.Scope, query, text(in.NextToken), int(value(in.MaxResults)), len(details))
	if err != nil {
		return nil, err
	}
	return &api.ListActionExecutionsOutput{ActionExecutionDetails: details[start:end], NextToken: next}, nil
}
func (s *Service) getState(tx Transaction, in *api.GetPipelineStateInput) (*api.GetPipelineStateOutput, error) {
	v, err := s.pipelineFor(tx, "GetPipelineState", text(in.Name))
	if err != nil {
		return nil, err
	}
	d, err := findDefinition(tx, v, v.Version)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Executions(v.Scope, v.Incarnation)
	if err != nil {
		return nil, err
	}
	polls, err := tx.SourcePolls(v.Scope, v.Incarnation)
	if err != nil {
		return nil, err
	}
	out := &api.GetPipelineStateOutput{PipelineName: new(api.PipelineName(v.Name)), PipelineVersion: new(api.PipelineVersion(v.Version)), Created: &v.CreatedAt, Updated: &v.UpdatedAt, StageStates: api.StageStateList{}}
	for i, st := range d.Declaration.Stages {
		state := api.StageState{StageName: st.Name, InboundTransitionState: &api.TransitionState{Enabled: new(api.Enabled(true))}, ActionStates: api.ActionStateList{}}
		for _, t := range v.Transitions {
			if t.Stage == text(st.Name) && t.Type == "Inbound" {
				state.InboundTransitionState = &api.TransitionState{Enabled: new(api.Enabled(!t.Disabled)), DisabledReason: optional[api.DisabledReason](t.Reason), LastChangedAt: &t.ChangedAt, LastChangedBy: optional[api.LastChangedBy](t.ChangedBy)}
			}
		}
		var latest *Execution
		var latestStageIndex int32
		for j := range rows {
			e := &rows[j]
			entered := false
			for _, a := range e.Actions {
				if a.StageName == text(st.Name) && !a.StartedAt.IsZero() {
					entered = true
					latestStageIndex = a.StageIndex
					break
				}
			}
			if entered {
				latest = e
			}
			if e.Version == v.Version && !terminal(e.Status) && e.StageIndex == int32(i) && !e.StageEntered {
				inbound := api.StageExecution{PipelineExecutionId: new(api.PipelineExecutionId(e.ID)), Status: new(api.StageExecutionStatus(e.Status)), Type: new(executionType(*e))}
				state.InboundExecution = &inbound
				state.InboundExecutions = append(state.InboundExecutions, inbound)
			}
		}
		if latest != nil {
			status := "InProgress"
			if latest.StageIndex > latestStageIndex || latest.Status == "Succeeded" {
				status = "Succeeded"
			} else if terminal(latest.Status) || latest.Status == "Stopping" {
				status = latest.Status
			}
			state.LatestExecution = &api.StageExecution{PipelineExecutionId: new(api.PipelineExecutionId(latest.ID)), Status: new(api.StageExecutionStatus(status)), Type: new(executionType(*latest))}
		}
		for _, decl := range st.Actions {
			ast := api.ActionState{ActionName: decl.Name}
			if text(decl.ActionTypeId.Provider) == "Lambda" {
				ast.EntityUrl = new(api.Url("https://console.aws.amazon.com/lambda/home?region=" + url.QueryEscape(v.Region) + "#/functions/" + url.PathEscape(string(decl.Configuration["FunctionName"]))))
			}
			if latest != nil {
				var a *ActionExecution
				for index := len(latest.Actions) - 1; index >= 0; index-- {
					candidate := &latest.Actions[index]
					if candidate.StageName == text(st.Name) && candidate.ActionName == text(decl.Name) {
						a = candidate
						break
					}
				}
				if a != nil && !a.StartedAt.IsZero() {
					ast.LatestExecution = &api.ActionExecution{ActionExecutionId: new(api.ActionExecutionId(a.ID)), Status: new(api.ActionExecutionStatus(a.Status)), LastStatusChange: &a.UpdatedAt, ExternalExecutionId: optional[api.ExecutionId](a.ExternalExecutionID), ExternalExecutionUrl: optional[api.Url](a.ExternalExecutionURL), Summary: optional[api.ExecutionSummary](a.Summary), ErrorDetails: actionError(*a)}
					ast.LatestExecution.LastUpdatedBy = optional[api.LastUpdatedBy](a.UpdatedBy)
					if text(decl.ActionTypeId.Provider) == "Lambda" {
						ast.LatestExecution.Summary = nil
					}
					if a.ApprovalToken != "" {
						ast.LatestExecution.ExternalExecutionId = nil
						if approvalNotificationFailed(*a) {
							ast.LatestExecution.Summary = nil
							ast.LatestExecution.LastStatusChange = nil
						}
					}
					if latest.UpdatedDefinition && a.ApprovalToken != "" && a.Status == "InProgress" {
						// Updating invalidates the current approval view without
						// rewriting the historical action execution outcome.
						ast.LatestExecution.Status = new(api.ActionExecutionStatus("Failed"))
						ast.LatestExecution.Summary = new(api.ExecutionSummary("The approval action has been canceled."))
					}
					if a.Status == "InProgress" && !latest.UpdatedDefinition {
						ast.LatestExecution.Token = optional[api.ActionExecutionToken](a.ApprovalToken)
					}
				}
				for _, revision := range latest.Revisions {
					if revision.ActionName == text(decl.Name) && text(decl.ActionTypeId.Category) == "Source" {
						ast.CurrentRevision = &api.ActionRevision{Created: optionalTimestamp(revision.CreatedAt), RevisionChangeId: optional[api.RevisionChangeIdentifier](revision.ChangeID), RevisionId: new(api.Revision(revision.RevisionID))}
					}
				}
				if latest.RollbackTargetID != "" && text(decl.ActionTypeId.Category) == "Source" && a != nil && a.ExternalExecutionID != "" {
					ast.CurrentRevision = &api.ActionRevision{RevisionId: new(api.Revision(a.ExternalExecutionID))}
				}
			}
			for _, p := range polls {
				if p.PipelineVersion != v.Version || p.StageName != text(st.Name) || p.ActionName != text(decl.Name) || p.ErrorCode == "" {
					continue
				}
				if ast.LatestExecution == nil || (ast.LatestExecution.LastStatusChange != nil && p.LastAttempt.After(*ast.LatestExecution.LastStatusChange)) {
					ast.CurrentRevision = nil
					ast.LatestExecution = &api.ActionExecution{Status: new(api.ActionExecutionStatus("Failed")), LastStatusChange: &p.LastAttempt,
						ErrorDetails: &api.ErrorDetails{Code: new(api.Code(p.ErrorCode)), Message: optional[api.Message](p.ErrorMessage)}}
				}
			}
			state.ActionStates = append(state.ActionStates, ast)
		}
		out.StageStates = append(out.StageStates, state)
	}
	return out, nil
}
