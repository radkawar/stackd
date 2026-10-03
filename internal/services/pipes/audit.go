package pipes

import (
	"context"
	"encoding/json"
	"errors"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/pipes"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

const exposedHeaders = "x-amzn-errortype,x-amzn-requestid,x-amzn-errormessage,x-amzn-trace-id,x-amz-apigw-id,date"

// The successful lifecycle and Conflict/NotFound projections are grounded in
// testdata/aws/scheduler_pipes/lifecycle_success.json, exact-request-ID native
// S3 CloudTrail records. These controls have no embedded resource index and no
// Pipes data-event projection is invented from target-side observations.
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, ok := awscatalog.LookupService("pipes")
	if !ok {
		return errors.New("Pipes model missing")
	}
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{
		Category: journal.CategoryManagement,
		ReadOnly: action == "DescribePipe" || action == "ListPipes" || action == "ListTagsForResource",
		Request: awsapi.DocumentProjection{
			PreserveNames: true,
			Fields: map[string]awsapi.FieldProjection{
				"Description": {Mode: awsapi.RedactValueField, Redaction: "***"},
				"SourceParameters.FilterCriteria.Filters.Pattern": {Mode: awsapi.RedactValueField, Redaction: "***"},
				"TargetParameters.InputTemplate":                  {Mode: awsapi.RedactValueField, Redaction: "***"},
				"EnrichmentParameters.InputTemplate":              {Mode: awsapi.RedactValueField, Redaction: "***"},
				"Tags":                                            {Mode: awsapi.IncludeField},
				"tags":                                            {Mode: awsapi.IncludeField},
			},
		},
	}
	if !projection.ReadOnly {
		projection.Response = &awsapi.DocumentProjection{PreserveNames: true}
	}
	call, err := projection.Call(model, operation, auditInput(in), out, rejected)
	if err != nil {
		return err
	}
	if !projection.ReadOnly && rejected == nil {
		var response map[string]any
		if len(call.ResponseElements) > 0 {
			if err = json.Unmarshal(call.ResponseElements, &response); err != nil {
				return err
			}
		}
		if response == nil {
			response = map[string]any{}
		}
		response["Access-Control-Expose-Headers"] = exposedHeaders
		call.ResponseElements, err = json.Marshal(response)
		if err != nil {
			return err
		}
	}
	if rejected != nil {
		switch rejected.Code {
		case "ConflictException":
			call.ErrorMessage = ""
			response := map[string]any{"Access-Control-Expose-Headers": exposedHeaders, "__type": rejected.Code, "message": rejected.Message}
			for key, value := range rejected.Details {
				response[key] = value
			}
			call.ResponseElements, err = json.Marshal(response)
			if err != nil {
				return err
			}
		case "NotFoundException":
			call.ErrorMessage = ""
		}
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func auditInput(input any) any {
	tags := func(in api.TagMap) api.TagMap {
		if in == nil {
			return nil
		}
		out := make(api.TagMap, len(in))
		for key := range in {
			out[key] = "***"
		}
		return out
	}
	switch in := input.(type) {
	case *api.CreatePipeInput:
		if in == nil {
			return in
		}
		out := *in
		out.Tags = tags(in.Tags)
		return &out
	case *api.TagResourceInput:
		if in == nil {
			return in
		}
		out := *in
		out.Tags = tags(in.Tags)
		return &out
	default:
		return input
	}
}
