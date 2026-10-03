package eventbridge

import (
	"context"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// PutEvents is the only implemented data operation. Response presence is a
// separate native contract: management reads omit outputs, data batches do not.
// service_{management,data}_events.json and eventbridge_archives_replays.json
// retain the native projections. Other implemented management projections use
// modeled public fields and command read semantics, not additional captures.
func auditProjection(action string) (apievents.Projection, bool) {
	p := apievents.Projection{Category: journal.CategoryManagement}
	switch action {
	case "PutEvents":
		p.Category = journal.CategoryData
		p.Request.Fields = map[string]awsapi.FieldProjection{"Entries.Detail": {Mode: awsapi.RedactField}}
		p.Response = &awsapi.DocumentProjection{}
	case "CreateArchive", "UpdateArchive":
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"CreationTime": {TimeLayout: time.RFC3339}}}
	case "CreateConnection", "UpdateConnection":
		p.Request.Fields = map[string]awsapi.FieldProjection{
			"AuthParameters.BasicAuthParameters.Password":                                    {Mode: awsapi.RedactField},
			"AuthParameters.ApiKeyAuthParameters.ApiKeyValue":                                {Mode: awsapi.RedactField},
			"AuthParameters.OAuthParameters.ClientParameters.ClientSecret":                   {Mode: awsapi.RedactField},
			"AuthParameters.InvocationHttpParameters.HeaderParameters.Value":                 {Mode: awsapi.RedactField},
			"AuthParameters.InvocationHttpParameters.QueryStringParameters.Value":            {Mode: awsapi.RedactField},
			"AuthParameters.InvocationHttpParameters.BodyParameters.Value":                   {Mode: awsapi.RedactField},
			"AuthParameters.OAuthParameters.OAuthHttpParameters.HeaderParameters.Value":      {Mode: awsapi.RedactField},
			"AuthParameters.OAuthParameters.OAuthHttpParameters.QueryStringParameters.Value": {Mode: awsapi.RedactField},
			"AuthParameters.OAuthParameters.OAuthHttpParameters.BodyParameters.Value":        {Mode: awsapi.RedactField},
		}
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"CreationTime": {TimeLayout: time.RFC3339}, "LastModifiedTime": {TimeLayout: time.RFC3339}, "LastAuthorizedTime": {TimeLayout: time.RFC3339},
		}}
	case "DeauthorizeConnection", "DeleteConnection":
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"CreationTime": {TimeLayout: time.RFC3339}, "LastModifiedTime": {TimeLayout: time.RFC3339}, "LastAuthorizedTime": {TimeLayout: time.RFC3339},
		}}
	case "CreateApiDestination", "UpdateApiDestination":
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"CreationTime": {TimeLayout: time.RFC3339}, "LastModifiedTime": {TimeLayout: time.RFC3339},
		}}
	case "DescribeApiDestination", "ListApiDestinations":
		p.ReadOnly = true
	case "DeleteApiDestination":
	case "DescribeConnection", "ListConnections":
		p.ReadOnly = true
	case "StartReplay":
		p.Request.Fields = map[string]awsapi.FieldProjection{
			"EventStartTime": {TimeLayout: time.RFC3339}, "EventEndTime": {TimeLayout: time.RFC3339},
		}
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"ReplayStartTime": {TimeLayout: time.RFC3339}}}
	case "CreateEventBus", "UpdateEventBus", "PutRule", "PutTargets", "RemoveTargets", "CancelReplay":
		p.Response = &awsapi.DocumentProjection{}
	case "DescribeEventBus", "ListEventBuses", "DescribeRule", "ListRules", "ListTargetsByRule", "ListRuleNamesByTarget", "ListTagsForResource", "TestEventPattern", "DescribeArchive", "ListArchives", "DescribeReplay", "ListReplays":
		p.ReadOnly = true
	case "DeleteEventBus", "DeleteRule", "EnableRule", "DisableRule", "TagResource", "UntagResource", "PutPermission", "RemovePermission", "DeleteArchive":
	default:
		return p, false
	}
	return p, true
}

func (s *Service) recordCall(ctx context.Context, action string, input, output any, rejected *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	projection, ok := auditProjection(action)
	if !ok {
		return nil
	}
	model, _ := awscatalog.LookupService("eventbridge")
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	// Native successful removals expose Force=false even when absent on the
	// API input. Project a detached DTO rather than changing caller input.
	switch in := input.(type) {
	case *api.DeleteRuleInput:
		if in != nil && in.Force == nil && rejected == nil {
			copy := *in
			copy.Force = ptr(api.Boolean(false))
			input = &copy
		}
	case *api.RemoveTargetsInput:
		if in != nil && in.Force == nil && rejected == nil {
			copy := *in
			copy.Force = ptr(api.Boolean(false))
			input = &copy
		}
	}
	call, err := projection.Call(model, operation, input, output, rejected)
	if err != nil {
		return err
	}
	call.APIVersion = model.Version
	// These specific missing-resource outcomes were ResourceNotFoundException
	// on the wire but UnknownError in CloudTrail. Archive/replay absence on
	// Describe, Update, Delete and Cancel retains ResourceNotFoundException.
	if rejected != nil {
		switch action {
		case "DescribeEventBus", "DescribeRule", "CreateArchive", "ListArchives", "ListRuleNamesByTarget":
			if rejected.Code == "ResourceNotFoundException" {
				call.ErrorCode, call.ErrorMessage = "UnknownError", "An unknown error occurred"
			}
		case "StartReplay":
			if in, ok := input.(*api.StartReplayInput); ok && in != nil && in.Destination != nil && len(in.Destination.FilterArns) > 0 && rejected.Code == "ResourceNotFoundException" {
				call.ErrorCode, call.ErrorMessage = "UnknownError", "An unknown error occurred"
			}
		}
		// These captured session-policy denials omit request/version fields.
		if (action == "CreateArchive" || action == "StartReplay" || action == "ListRuleNamesByTarget") && rejected.Code == "AccessDeniedException" {
			call.ErrorCode = "AccessDenied"
			call.RequestParameters = nil
			call.APIVersion = ""
		}
	}
	if in, ok := input.(*api.PutEventsInput); ok && in != nil {
		seen := make(map[string]bool, len(in.Entries))
		for _, entry := range in.Entries {
			bus, wire := busKey(ctx, value(entry.EventBusName))
			if wire != nil {
				continue
			}
			arn := bus.ARN()
			if seen[arn] {
				continue
			}
			seen[arn] = true
			call.EventResources = append(call.EventResources, journal.APIEventResource{Type: "AWS::Events::EventBus", ARN: arn})
		}
	}
	// Native EventBridge data delivery belongs to the caller, even when bus
	// policy authorizes admission into another account's event bus.
	scope := scopeFor(ctx)
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, call)
}

// finishCall runs only after a command's resource callback closes. Mutations
// record success in that callback; pure reads record success here, never through
// a borrowed read transaction. Rejected outcomes have no response document.
func finishCall[O any](s *Service, ctx context.Context, action string, input any, output **O, rejected **awswire.Error, read bool) {
	if *rejected == nil && !read {
		return
	}
	if err := s.recordCall(ctx, action, input, *output, *rejected); err != nil {
		*output, *rejected = nil, wireError(err)
	}
}

func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
