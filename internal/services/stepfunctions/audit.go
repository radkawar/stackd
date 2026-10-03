package stepfunctions

import (
	"context"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Management projections follow testdata/aws/stepfunctions/observability.json.
// Classification follows the current procedure-cloud-trail documentation:
// StartSyncExecution and GetActivityTask are data calls, while task-token
// callbacks remain management calls. Data events are not LookupEvents history.
func auditProjection(action string) apievents.Projection {
	p := apievents.Projection{Category: journal.CategoryManagement}
	p.Request.Fields = map[string]awsapi.FieldProjection{
		"definition": {Mode: awsapi.RedactValueField},
		"input":      {Mode: awsapi.RedactValueField},
		"output":     {Mode: awsapi.RedactValueField},
		"error":      {Mode: awsapi.RedactValueField},
		"cause":      {Mode: awsapi.RedactValueField},
		"taskToken":  {Mode: awsapi.RedactValueField},
	}
	switch action {
	case "StartSyncExecution", "GetActivityTask":
		p.Category = journal.CategoryData
	case "DescribeActivity", "DescribeExecution", "DescribeMapRun", "DescribeStateMachine", "DescribeStateMachineAlias", "DescribeStateMachineForExecution", "GetExecutionHistory", "ListActivities", "ListExecutions", "ListMapRuns", "ListStateMachineAliases", "ListStateMachines", "ListStateMachineVersions", "ListTagsForResource":
		p.ReadOnly = true
	}
	switch action {
	case "CreateActivity", "CreateStateMachine", "CreateStateMachineAlias", "UpdateStateMachine", "UpdateStateMachineAlias", "PublishStateMachineVersion", "StartExecution", "StartSyncExecution", "StopExecution", "RedriveExecution", "TestState", "ValidateStateMachineDefinition":
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"creationDate": {TimeLayout: time.RFC3339},
			"updateDate":   {TimeLayout: time.RFC3339},
			"startDate":    {TimeLayout: time.RFC3339},
			"stopDate":     {TimeLayout: time.RFC3339},
			"redriveDate":  {TimeLayout: time.RFC3339},
			"input":        {Mode: awsapi.RedactValueField},
			"output":       {Mode: awsapi.RedactValueField},
			"error":        {Mode: awsapi.RedactValueField},
			"cause":        {Mode: awsapi.RedactValueField},
		}}
	}
	return p
}

func (s *Service) recordCall(ctx context.Context, action string, input, output any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("stepfunctions")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	// Project detached inputs: native management records include these defaults
	// without mutating the caller's request or exposing execution payloads.
	switch in := input.(type) {
	case *api.CreateStateMachineInput:
		if in != nil {
			copy := *in
			if copy.Publish == nil {
				copy.Publish = new(api.Publish(false))
			}
			if copy.Type == nil {
				copy.Type = new(api.StateMachineType("STANDARD"))
			}
			input = &copy
		}
	case *api.UpdateStateMachineInput:
		if in != nil {
			copy := *in
			if copy.Publish == nil {
				copy.Publish = new(api.Publish(false))
			}
			input = &copy
		}
	case *api.GetExecutionHistoryInput:
		if in != nil {
			copy := *in
			if copy.MaxResults == nil {
				copy.MaxResults = new(api.PageSize(0))
			}
			if copy.ReverseOrder == nil {
				copy.ReverseOrder = new(api.ReverseOrder(false))
			}
			if copy.IncludeExecutionData == nil {
				copy.IncludeExecutionData = new(api.IncludeExecutionDataGetExecutionHistory(true))
			}
			input = &copy
		}
	}
	call, err := auditProjection(action).Call(model, op, input, output, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	// Native management events omit resources, independently of their request
	// ARNs. Data selectors need the documented resource type and exact ARN.
	var resource, kind string
	switch in := input.(type) {
	case *api.StartSyncExecutionInput:
		if in != nil {
			resource, kind = value(in.StateMachineArn), "AWS::StepFunctions::StateMachine"
		}
	case *api.GetActivityTaskInput:
		if in != nil {
			resource, kind = value(in.ActivityArn), "AWS::StepFunctions::Activity"
		}
	}
	if resource != "" {
		owner, resourceKind, _, _, err := parseResourceARN(resource)
		if err == nil && ((kind == "AWS::StepFunctions::StateMachine" && resourceKind == "stateMachine") || (kind == "AWS::StepFunctions::Activity" && resourceKind == "activity")) {
			call.EventResources = []journal.APIEventResource{{AccountID: owner.AccountID, Type: kind, ARN: resource}}
		}
	}
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
