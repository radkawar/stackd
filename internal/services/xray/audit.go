package xray

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/xray"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Ingestion owns acceptance. Carry only accepted trace IDs to the recorder,
// rather than reparsing documents or guessing acceptance from nonunique IDs.
type traceAuditKey struct{}
type traceAudit struct {
	TraceIDs []string `json:"traceSegmentDocuments"`
}

// Deletion's wire result is empty; native audit retains the resolved identity.
type groupAuditKey struct{}
type groupAudit struct {
	ARN string `json:"groupARN"`
}

func auditProjection(action string) (apievents.Projection, bool) {
	p := apievents.Projection{Category: journal.CategoryManagement}
	switch action {
	case "PutResourcePolicy":
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"ResourcePolicy.LastUpdatedTime": {TimeLayout: time.RFC3339},
		}}
	case "CreateSamplingRule", "UpdateSamplingRule", "DeleteSamplingRule":
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"SamplingRuleRecord.CreatedAt":  {TimeLayout: time.RFC3339},
			"SamplingRuleRecord.ModifiedAt": {TimeLayout: time.RFC3339},
		}}
	case "CreateGroup", "UpdateGroup", "DeleteGroup":
		p.Response = &awsapi.DocumentProjection{}
	case "TagResource", "UntagResource":
	case "ListResourcePolicies", "GetSamplingRules", "GetSamplingStatisticSummaries", "GetGroup", "GetGroups", "ListTagsForResource":
		p.ReadOnly = true
	case "DeleteResourcePolicy":
	case "PutTraceSegments":
		p.Category = journal.CategoryData
		p.Request.Fields = map[string]awsapi.FieldProjection{"TraceSegmentDocuments": {Mode: awsapi.OmitField}}
		p.Response = &awsapi.DocumentProjection{}
	case "PutTelemetryRecords":
		p.Category = journal.CategoryData
		p.Request.Fields = map[string]awsapi.FieldProjection{
			"TelemetryRecords.Timestamp": {TimeLayout: time.RFC3339},
		}
	case "BatchGetTraces", "GetTraceGraph":
		p.Category, p.ReadOnly = journal.CategoryData, true
	case "GetTraceSummaries", "GetServiceGraph", "GetTimeSeriesServiceStatistics":
		p.Category, p.ReadOnly = journal.CategoryData, true
		p.Request.Fields = map[string]awsapi.FieldProjection{
			"StartTime": {TimeLayout: time.RFC3339},
			"EndTime":   {TimeLayout: time.RFC3339},
		}
	case "GetSamplingTargets":
		p.Category, p.ReadOnly = journal.CategoryData, true
		p.Request.Fields = map[string]awsapi.FieldProjection{
			"SamplingStatisticsDocuments.Timestamp":      {TimeLayout: time.RFC3339},
			"SamplingBoostStatisticsDocuments.Timestamp": {TimeLayout: time.RFC3339},
		}
	default:
		return p, false
	}
	return p, true
}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	projection, supported := auditProjection(action)
	if !supported {
		return nil
	}
	model, ok := awscatalog.LookupService("xray")
	if !ok {
		return errors.New("X-Ray audit service metadata is missing")
	}
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	if request, ok := in.(*api.PutResourcePolicyRequest); ok && request != nil {
		copy := *request
		if copy.BypassPolicyLockoutCheck == nil {
			copy.BypassPolicyLockoutCheck = new(api.Boolean(false))
		}
		in = &copy
	}
	if request, ok := in.(*api.GetSamplingTargetsRequest); ok && request != nil && rejected == nil {
		// Native audit records materialize omitted counters as zero, without
		// changing the request used by admission or the generated field names.
		copy := *request
		cloned := false
		for i, document := range request.SamplingStatisticsDocuments {
			if document.RequestCount != nil && document.SampledCount != nil && document.BorrowCount != nil {
				continue
			}
			if !cloned {
				copy.SamplingStatisticsDocuments = append(api.SamplingStatisticsDocumentList(nil), request.SamplingStatisticsDocuments...)
				cloned = true
			}
			if document.RequestCount == nil {
				document.RequestCount = new(api.RequestCount(0))
			}
			if document.SampledCount == nil {
				document.SampledCount = new(api.SampledCount(0))
			}
			if document.BorrowCount == nil {
				document.BorrowCount = new(api.BorrowCount(0))
			}
			copy.SamplingStatisticsDocuments[i] = document
		}
		if cloned {
			in = &copy
		}
	}
	parameters, ownsParameters := in.(telemetryAuditParameters)
	if ownsParameters {
		in = nil
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	if ownsParameters {
		call.RequestParameters = json.RawMessage(parameters)
	}
	if string(call.RequestParameters) == "{}" {
		call.RequestParameters = json.RawMessage("null")
	}
	if action == "PutTraceSegments" {
		call.RequestParameters = json.RawMessage("null")
		if audit, ok := ctx.Value(traceAuditKey{}).(*traceAudit); ok && rejected == nil {
			call.RequestParameters, err = json.Marshal(audit)
			if err != nil {
				return err
			}
		}
	}
	if action == "DeleteGroup" && rejected == nil {
		if audit, ok := ctx.Value(groupAuditKey{}).(*groupAudit); ok {
			call.ResponseElements, err = json.Marshal(audit)
			if err != nil {
				return err
			}
		}
	}
	if projection.Category == journal.CategoryData {
		// Native trace data events have no resource ARN or resource account.
		call.EventResources = []journal.APIEventResource{{Type: "AWS::XRay::Trace"}}
	}
	if rejected != nil {
		switch rejected.Code {
		case "MalformedPolicyDocumentException":
			call.RequestParameters, call.ErrorMessage = json.RawMessage("null"), ""
		case "AccessDenied", "AccessDeniedException":
			call.ErrorCode = "AccessDenied"
			call.RequestParameters = json.RawMessage("null")
		case "InternalFailure":
			if action == "TagResource" {
				call.RequestParameters = json.RawMessage("null")
			}
			if action == "PutTelemetryRecords" {
				call.ErrorCode, call.ErrorMessage = "UnknownError", "An unknown error occurred"
			}
		case "ValidationException", "SerializationException":
			call.RequestParameters = json.RawMessage("null")
		}
		// Sampling selector validation runs before the request is included in
		// native audit. Other InvalidRequestException failures retain it.
		if rejected.Code == "InvalidRequestException" {
			var name, arn string
			var samplingSelector bool
			switch request := in.(type) {
			case *api.CreateSamplingRuleRequest:
				if request != nil && request.SamplingRule != nil {
					name, arn, samplingSelector = value(request.SamplingRule.RuleName), value(request.SamplingRule.RuleARN), true
				}
			case *api.UpdateSamplingRuleRequest:
				if request != nil && request.SamplingRuleUpdate != nil {
					name, arn, samplingSelector = value(request.SamplingRuleUpdate.RuleName), value(request.SamplingRuleUpdate.RuleARN), true
				}
			case *api.DeleteSamplingRuleRequest:
				if request != nil {
					name, arn, samplingSelector = value(request.RuleName), value(request.RuleARN), true
				}
			}
			if samplingSelector && (name == "") == (arn == "") {
				call.RequestParameters = json.RawMessage("null")
			}
		}
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
