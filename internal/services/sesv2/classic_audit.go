package sesv2

import (
	"context"
	"encoding/json"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	classic "stackd/internal/awsapi/ses"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
	"strings"
)

func (s *Service) recordClassicCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ses")
	op, _ := model.Operation(action)
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Describe"), Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
		"Message": {Mode: awsapi.OmitField}, "RawMessage": {Mode: awsapi.OmitField}, "Destination": {Mode: awsapi.OmitField}, "Destinations": {Mode: awsapi.OmitField}, "ReplyToAddresses": {Mode: awsapi.OmitField}, "ReturnPath": {Mode: awsapi.OmitField}, "TemplateData": {Mode: awsapi.OmitField}, "DefaultTemplateData": {Mode: awsapi.OmitField},
	}}}
	switch action {
	case "SendEmail", "SendRawEmail", "SendTemplatedEmail", "SendBulkTemplatedEmail":
		projection.Category = journal.CategoryData
	case "CreateTemplate", "UpdateTemplate":
		projection.Request.Fields["Template"] = awsapi.FieldProjection{Mode: awsapi.OmitField}
	}
	call, e := projection.Call(model, op, in, out, rejected)
	if e != nil {
		return e
	}
	scope := scopeFor(ctx)
	var ids []string
	switch v := out.(type) {
	case *classic.SendEmailOutput:
		if v != nil {
			ids = append(ids, value(v.MessageId))
		}
	case *classic.SendRawEmailOutput:
		if v != nil {
			ids = append(ids, value(v.MessageId))
		}
	case *classic.SendTemplatedEmailOutput:
		if v != nil {
			ids = append(ids, value(v.MessageId))
		}
	case *classic.SendBulkTemplatedEmailOutput:
		if v != nil {
			for _, entry := range v.Status {
				if entry.MessageId != nil {
					ids = append(ids, value(entry.MessageId))
				}
			}
		}
	}
	if len(ids) == 1 {
		call.AdditionalEventData, e = json.Marshal(map[string]string{"sesMessageId": ids[0]})
		if e != nil {
			return e
		}
	}
	if rejected == nil && len(ids) > 0 {
		call.EventResources, e = s.acceptedResources(ctx, scope, ids)
		if e != nil {
			return e
		}
	}
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
