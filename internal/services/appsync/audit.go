package appsync

import (
	"context"
	"errors"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
	"strings"
)

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, ok := awscatalog.LookupService("appsync")
	if !ok {
		return errors.New("AppSync model missing")
	}
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	// Redact caller code, schema and bearer API key material. This is a management
	// event projection; it makes no claim to native CloudTrail byte equivalence.
	fields := map[string]awsapi.FieldProjection{}
	for _, path := range []string{"definition", "code", "requestMappingTemplate", "responseMappingTemplate", "apiKey.id", "apiKeys.id", "functionConfiguration.code", "functionConfiguration.requestMappingTemplate", "functionConfiguration.responseMappingTemplate", "resolver.code", "resolver.requestMappingTemplate", "resolver.responseMappingTemplate", "functions.code", "resolvers.code"} {
		fields[path] = awsapi.FieldProjection{Mode: awsapi.RedactValueField, Redaction: "***"}
	}
	if strings.Contains(action, "ApiKey") {
		fields["id"] = awsapi.FieldProjection{Mode: awsapi.RedactValueField, Redaction: "***"}
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List"), Request: awsapi.DocumentProjection{PreserveNames: true, Fields: fields}}
	if !projection.ReadOnly {
		projection.Response = &awsapi.DocumentProjection{PreserveNames: true, Fields: fields}
	}
	if rejected != nil {
		switch action {
		case "CreateResolver", "UpdateResolver", "CreateFunction", "UpdateFunction", "StartSchemaCreation":
			// Compiler diagnostics can include source lines. Keep the code, not its text.
			sanitized := *rejected
			sanitized.Message = "AppSync definition rejected."
			sanitized.Details = nil
			rejected = &sanitized
		}
	}
	call, e := projection.Call(model, operation, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	scope := awsctx.FromContext(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
