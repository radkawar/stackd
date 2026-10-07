package glue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"

	api "stackd/internal/awsapi/glue"
)

func registerWorkflows(s *Service) {
	registerControl(s, "CreateWorkflow", s.createWorkflow)
	registerControl(s, "UpdateWorkflow", s.updateWorkflow)
	registerControl(s, "DeleteWorkflow", s.deleteWorkflow)
	registerControl(s, "GetWorkflow", s.getWorkflow)
	registerControl(s, "ListWorkflows", s.listWorkflows)
	registerControl(s, "BatchGetWorkflows", s.batchGetWorkflows)
	registerControl(s, "StartWorkflowRun", s.startWorkflowRun)
	registerControl(s, "GetWorkflowRun", s.getWorkflowRun)
	registerControl(s, "GetWorkflowRuns", s.getWorkflowRuns)
	registerControl(s, "GetWorkflowRunProperties", s.getWorkflowRunProperties)
	registerControl(s, "PutWorkflowRunProperties", s.putWorkflowRunProperties)
	registerControl(s, "StopWorkflowRun", s.stopWorkflowRun)
	registerControl(s, "ResumeWorkflowRun", s.resumeWorkflowRun)
	registerTriggers(s)
	registerSecurity(s)
	registerTags(s)
}
func workflowName(name string) error {
	if strings.TrimSpace(name) == "" {
		return failure("InvalidInputException", "Name must not be empty.")
	}
	return nil
}
func workflowTime(t time.Time) *api.TimestampValue { return new(api.TimestampValue(t.UTC())) }
func (s *Service) workflowAccess(ctx context.Context, tx Reader, action string, key ResourceKey) (WorkflowRecord, error) {
	v, err := tx.Workflow(key)
	if err != nil {
		return v, err
	}
	return v, s.authorize(ctx, tx, action, key.Scope, key.ARN("workflow"), v.Tags)
}
func (s *Service) createWorkflow(ctx context.Context, tx Transaction, in *api.CreateWorkflowInput) (*api.CreateWorkflowOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if err := workflowName(key.Name); err != nil {
		return nil, err
	}
	if in.MaxConcurrentRuns != nil && *in.MaxConcurrentRuns < 1 {
		return nil, failure("InvalidInputException", "MaxConcurrentRuns must be positive.")
	}
	tags, err := workflowInputTags(in.Tags)
	if err != nil {
		return nil, err
	}
	if err = s.authorizeCreate(ctx, tx, "CreateWorkflow", key.Scope, key.ARN("workflow"), tags); err != nil {
		return nil, err
	}
	if _, err = tx.Workflow(key); err == nil {
		return nil, failure("AlreadyExistsException", "Workflow already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := workflowTime(s.clock.Now())
	w := api.Workflow{Name: in.Name, CreatedOn: now, LastModifiedOn: now, DefaultRunProperties: in.DefaultRunProperties, MaxConcurrentRuns: in.MaxConcurrentRuns}
	if in.Description != nil {
		w.Description = new(api.GenericString(*in.Description))
	}
	if err = tx.PutWorkflow(WorkflowRecord{Key: key, Workflow: w, Tags: tags}); err != nil {
		return nil, err
	}
	return &api.CreateWorkflowOutput{Name: in.Name}, nil
}
func (s *Service) updateWorkflow(ctx context.Context, tx Transaction, in *api.UpdateWorkflowInput) (*api.UpdateWorkflowOutput, error) {
	v, err := s.workflowAccess(ctx, tx, "UpdateWorkflow", ResourceKey{scopeFor(ctx), value(in.Name)})
	if err != nil {
		return nil, err
	}
	if in.MaxConcurrentRuns != nil && *in.MaxConcurrentRuns < 1 {
		return nil, failure("InvalidInputException", "MaxConcurrentRuns must be positive.")
	}
	v.Workflow.MaxConcurrentRuns = in.MaxConcurrentRuns
	if in.Description != nil {
		v.Workflow.Description = new(api.GenericString(*in.Description))
	}
	if in.DefaultRunProperties != nil {
		v.Workflow.DefaultRunProperties = in.DefaultRunProperties
	}
	v.Workflow.LastModifiedOn = workflowTime(s.clock.Now())
	if err = tx.PutWorkflow(v); err != nil {
		return nil, err
	}
	return &api.UpdateWorkflowOutput{Name: in.Name}, nil
}
func (s *Service) deleteWorkflow(ctx context.Context, tx Transaction, in *api.DeleteWorkflowInput) (*api.DeleteWorkflowOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	v, err := tx.Workflow(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err = s.authorize(ctx, tx, "DeleteWorkflow", key.Scope, key.ARN("workflow"), v.Tags); err != nil {
		return nil, err
	}
	if err = tx.DeleteWorkflow(key); err != nil {
		return nil, err
	}
	return &api.DeleteWorkflowOutput{Name: in.Name}, nil
}
func (s *Service) workflowView(tx Reader, v WorkflowRecord, graph bool) (api.Workflow, error) {
	out := v.Workflow
	runs, err := tx.WorkflowRuns(v.Key)
	if err != nil {
		return out, err
	}
	if len(runs) > 0 {
		w := workflowRunView(runs[0], graph)
		if err = s.workflowRunGraph(tx, runs[0], &w); err != nil {
			return out, err
		}
		out.LastRun = &w
	}
	if graph {
		triggers, err := tx.Triggers(v.Key.Scope)
		if err != nil {
			return out, err
		}
		out.Graph = workflowGraph(workflowNodes(triggers, v.Key.Name, ""))
		for i := range out.Graph.Nodes {
			node := &out.Graph.Nodes[i]
			if node.TriggerDetails != nil {
				node.TriggerDetails.Trigger.WorkflowName = new(api.NameString(v.Key.Name))
			}
		}
	}
	return out, nil
}
func (s *Service) getWorkflow(ctx context.Context, tx Transaction, in *api.GetWorkflowInput) (*api.GetWorkflowOutput, error) {
	v, err := s.workflowAccess(ctx, tx, "GetWorkflow", ResourceKey{scopeFor(ctx), value(in.Name)})
	if err != nil {
		return nil, err
	}
	out, err := s.workflowView(tx, v, in.IncludeGraph != nil && bool(*in.IncludeGraph))
	return &api.GetWorkflowOutput{Workflow: &out}, err
}
func (s *Service) listWorkflows(ctx context.Context, tx Transaction, in *api.ListWorkflowsInput) (*api.ListWorkflowsOutput, error) {
	scope := scopeFor(ctx)
	if err := s.authorize(ctx, tx, "ListWorkflows", scope, "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Workflows(scope)
	if err != nil {
		return nil, err
	}
	rows, token, err := workflowPage(rows, func(v WorkflowRecord) string { return v.Key.Name }, "workflows/"+workflowScope(scope), in.MaxResults, in.NextToken, 25)
	if err != nil {
		return nil, err
	}
	out := &api.ListWorkflowsOutput{NextToken: token, Workflows: api.WorkflowNames{}}
	for _, v := range rows {
		out.Workflows = append(out.Workflows, api.NameString(v.Key.Name))
	}
	return out, nil
}
func (s *Service) batchGetWorkflows(ctx context.Context, tx Transaction, in *api.BatchGetWorkflowsInput) (*api.BatchGetWorkflowsOutput, error) {
	out := &api.BatchGetWorkflowsOutput{Workflows: api.Workflows{}, MissingWorkflows: api.WorkflowNames{}}
	for _, name := range in.Names {
		v, err := s.workflowAccess(ctx, tx, "BatchGetWorkflows", ResourceKey{scopeFor(ctx), string(name)})
		if errors.Is(err, ErrNotFound) {
			out.MissingWorkflows = append(out.MissingWorkflows, name)
			continue
		}
		if err != nil {
			return nil, err
		}
		w, err := s.workflowView(tx, v, in.IncludeGraph != nil && bool(*in.IncludeGraph))
		if err != nil {
			return nil, err
		}
		out.Workflows = append(out.Workflows, w)
	}
	return out, nil
}
func (s *Service) getWorkflowRun(ctx context.Context, tx Transaction, in *api.GetWorkflowRunInput) (*api.GetWorkflowRunOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if _, err := s.workflowAccess(ctx, tx, "GetWorkflowRun", key); err != nil {
		return nil, err
	}
	v, err := tx.WorkflowRun(key, value(in.RunId))
	if err != nil {
		return nil, err
	}
	out := workflowRunView(v, in.IncludeGraph != nil && bool(*in.IncludeGraph))
	if err = s.workflowRunGraph(tx, v, &out); err != nil {
		return nil, err
	}
	return &api.GetWorkflowRunOutput{Run: &out}, nil
}
func (s *Service) getWorkflowRuns(ctx context.Context, tx Transaction, in *api.GetWorkflowRunsInput) (*api.GetWorkflowRunsOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if _, err := s.workflowAccess(ctx, tx, "GetWorkflowRuns", key); err != nil {
		return nil, err
	}
	rows, err := tx.WorkflowRuns(key)
	if err != nil {
		return nil, err
	}
	rows, token, err := workflowPage(rows, func(v WorkflowRunRecord) string { return v.ID }, key.ARN("workflow")+"/runs", in.MaxResults, in.NextToken, 1000)
	if err != nil {
		return nil, err
	}
	out := &api.GetWorkflowRunsOutput{NextToken: token, Runs: api.WorkflowRuns{}}
	for _, v := range rows {
		w := workflowRunView(v, in.IncludeGraph != nil && bool(*in.IncludeGraph))
		if err = s.workflowRunGraph(tx, v, &w); err != nil {
			return nil, err
		}
		out.Runs = append(out.Runs, w)
	}
	return out, nil
}
func (s *Service) getWorkflowRunProperties(ctx context.Context, tx Transaction, in *api.GetWorkflowRunPropertiesInput) (*api.GetWorkflowRunPropertiesOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if _, err := s.workflowAccess(ctx, tx, "GetWorkflowRunProperties", key); err != nil {
		return nil, err
	}
	v, err := tx.WorkflowRun(key, value(in.RunId))
	if err != nil {
		return nil, err
	}
	return &api.GetWorkflowRunPropertiesOutput{RunProperties: v.Properties}, nil
}
func (s *Service) putWorkflowRunProperties(ctx context.Context, tx Transaction, in *api.PutWorkflowRunPropertiesInput) (*api.PutWorkflowRunPropertiesOutput, error) {
	key := ResourceKey{scopeFor(ctx), value(in.Name)}
	if _, err := s.workflowAccess(ctx, tx, "PutWorkflowRunProperties", key); err != nil {
		return nil, err
	}
	v, err := tx.WorkflowRun(key, value(in.RunId))
	if err != nil {
		return nil, err
	}
	if v.Properties == nil {
		v.Properties = api.WorkflowRunProperties{}
	}
	maps.Copy(v.Properties, in.RunProperties)
	if err = tx.PutWorkflowRun(v); err != nil {
		return nil, err
	}
	return &api.PutWorkflowRunPropertiesOutput{}, nil
}
func workflowScope(s Scope) string { return s.Partition + "/" + s.AccountID + "/" + s.Region }

type workflowCursor struct{ Collection, After string }

func workflowPage[T any, N ~int32](rows []T, key func(T) string, collection string, limit *N, token *api.GenericString, max int) ([]T, *api.GenericString, error) {
	n := max
	if limit != nil {
		n = int(*limit)
	}
	if n < 1 || n > max {
		return nil, nil, failure("InvalidInputException", "MaxResults is out of range.")
	}
	start := 0
	if value(token) != "" {
		data, err := base64.RawURLEncoding.DecodeString(value(token))
		var c workflowCursor
		if err != nil || json.Unmarshal(data, &c) != nil || c.Collection != collection {
			return nil, nil, failure("InvalidInputException", "Invalid pagination token.")
		}
		found := false
		for i, v := range rows {
			if key(v) == c.After {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, nil, failure("InvalidInputException", "Pagination token is no longer valid.")
		}
	}
	end := min(start+n, len(rows))
	if end == len(rows) {
		return rows[start:end], nil, nil
	}
	data, _ := json.Marshal(workflowCursor{collection, key(rows[end-1])})
	return rows[start:end], new(api.GenericString(base64.RawURLEncoding.EncodeToString(data))), nil
}
