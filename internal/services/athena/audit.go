package athena

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Athena's documented CloudTrail projection masks SQL instead of copying
// arbitrary customer literals into management-event storage.
// https://docs.aws.amazon.com/athena/latest/ug/monitor-with-cloudtrail.html
var auditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"QueryString":         {Mode: awsapi.RedactValueField, Redaction: "***OMITTED***"},
	"QueryStatement":      {Mode: awsapi.RedactValueField, Redaction: "***OMITTED***"},
	"ExecutionParameters": {Mode: awsapi.RedactValueField, Redaction: "***OMITTED***"},
}}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, ok := awscatalog.LookupService("athena")
	if !ok {
		return errors.New("athena audit metadata is missing")
	}
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "BatchGet"), Request: auditRequest}
	// Query text and result data are available only through their authorized APIs,
	// never copied into CloudTrail response elements.
	if action == "StartQueryExecution" || action == "CreateNamedQuery" {
		projection.Response = &awsapi.DocumentProjection{}
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
