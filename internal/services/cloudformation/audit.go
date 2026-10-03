package cloudformation

import (
	"context"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// The owned native lifecycle capture calibrates omission separately from Smithy
// sensitivity: CloudFormation does not log TemplateBody or request tokens on
// stack/execute operations, and failures omit request/response documents.
func (s *Service) recordCall(ctx context.Context, d awsapi.DecodedRequest, input, output any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	name := string(d.Operation.Name)
	readOnly := strings.HasPrefix(name, "Describe") || strings.HasPrefix(name, "List") || strings.HasPrefix(name, "Get") || name == "ValidateTemplate"
	call := journal.APICallCompleted{EventID: apievents.EventID(ctx), EventSource: "cloudformation.amazonaws.com", EventName: name, Category: journal.CategoryManagement, ReadOnly: readOnly}
	model, _ := awscatalog.LookupService("cloudformation")
	if rejected != nil {
		call.ErrorCode = apievents.ErrorName(model, d.Operation, rejected.Code)
		if rejected.Code == "ValidationError" {
			call.ErrorCode = "ValidationException"
		}
		call.ErrorMessage = rejected.Message
	} else {
		allowed := map[string]bool{"StackName": true, "ChangeSetName": true, "LogicalResourceId": true, "PhysicalResourceId": true, "NextToken": true, "ExportName": true, "StackStatusFilter": true}
		switch name {
		case "CreateStack", "UpdateStack":
			for _, key := range []string{"Capabilities", "Tags", "RoleARN", "Parameters", "DisableRollback", "OnFailure", "EnableTerminationProtection", "UsePreviousTemplate"} {
				allowed[key] = true
			}
		case "CreateChangeSet":
			for _, key := range []string{"Capabilities", "Tags", "RoleARN", "Parameters", "ClientToken", "Description", "UsePreviousTemplate"} {
				allowed[key] = true
			}
		case "UpdateTerminationProtection":
			allowed["EnableTerminationProtection"] = true
		case "DeleteStack":
			allowed["RoleARN"] = true
			allowed["RetainResources"] = true
		}
		shape, _ := model.Shape(d.Operation.Input)
		projection := awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{}}
		for _, member := range shape.Members {
			if !allowed[member.Name] {
				projection.Fields[member.Name] = awsapi.FieldProjection{Mode: awsapi.OmitField}
			}
		}
		projection.Fields["Parameters.ParameterValue"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
		projection.Fields["Parameters.UsePreviousValue"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
		projection.Fields["Parameters.ResolvedValue"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
		if name != "ValidateTemplate" {
			var e error
			call.RequestParameters, e = awsapi.EncodeDocument(model, d.Operation.Input, input, &projection)
			if e != nil {
				return e
			}
		}
		var responseField string
		switch name {
		case "CreateStack", "UpdateStack", "RollbackStack", "UpdateTerminationProtection":
			responseField = "StackId"
		case "CreateChangeSet":
			responseField = "Id"
		}
		if responseField != "" {
			shape, _ = model.Shape(d.Operation.Output)
			p := awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{}}
			for _, m := range shape.Members {
				if m.Name != responseField {
					p.Fields[m.Name] = awsapi.FieldProjection{Mode: awsapi.OmitField}
				}
			}
			var e error
			call.ResponseElements, e = awsapi.EncodeDocument(model, d.Operation.Output, output, &p)
			if e != nil {
				return e
			}
		}
	}
	m := awsctx.FromContext(ctx)
	return s.recorder.Record(ctx, journal.Envelope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region, At: s.clock.Now()}, call)
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, d, nil, nil, rejected)
}
