package apigatewayv2

import (
	"context"
	"net/url"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("apigatewayv2")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get"), Response: &awsapi.DocumentProjection{}}
	switch action {
	case "CreateApi":
		projection.Response.Fields = map[string]awsapi.FieldProjection{"CreatedDate": {TimeLayout: time.RFC3339}}
		// Native API creation omits empty tags, unlike stage creation.
		if response, ok := out.(*api.CreateApiOutput); ok && response != nil && len(response.Tags) == 0 {
			projection.Response.Fields["Tags"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
		}
	case "CreateDeployment":
		projection.Response.Fields = map[string]awsapi.FieldProjection{"CreatedDate": {TimeLayout: time.RFC3339}}
	case "CreateStage", "UpdateStage":
		projection.Request.Fields = map[string]awsapi.FieldProjection{
			"StageVariables": {Mode: awsapi.RedactValueField, Redaction: "***"},
		}
		projection.Response.Fields = map[string]awsapi.FieldProjection{
			"CreatedDate":     {TimeLayout: time.RFC3339},
			"LastUpdatedDate": {TimeLayout: time.RFC3339},
			"StageVariables":  {Mode: awsapi.RedactValueField, Redaction: "***"},
		}
		if request, ok := in.(*api.UpdateStageInput); ok && request != nil && request.StageName != nil {
			// UpdateStage logs its URI label, while CreateStage logs the body
			// member. Escape all but RFC 3986 unreserved characters, including $.
			copy := *request
			text(&copy.StageName, strings.ReplaceAll(url.QueryEscape(value(request.StageName)), "+", "%20"))
			in = &copy
		}
	case "CreateIntegration", "CreateAuthorizer", "CreateRoute", "DeleteApi", "GetApi":
		// The modeled lower-camel documents match the captured native fields.
	default:
		// TODO: Comeback calibrate uncaptured operations, successful reads and
		// remaining errors against native CloudTrail. Retain generic outcomes.
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventSource = "apigateway.amazonaws.com"
	if rejected != nil {
		switch {
		case action == "CreateRoute" && rejected.Code == "BadRequestException":
			// Native validation failures carry the actual response message in
			// responseElements rather than the event's errorMessage field.
			response := &api.BadRequestException{}
			text(&response.Message, rejected.Message)
			call.ResponseElements, err = awsapi.EncodeDocument(model, "com.amazonaws.apigatewayv2#BadRequestException", response, &awsapi.DocumentProjection{})
			if err != nil {
				return err
			}
			call.ErrorMessage = ""
		case action == "GetApi" && rejected.Code == "NotFoundException":
			call.ErrorMessage = ""
		}
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
