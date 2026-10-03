package sesv2

import (
	"context"
	"encoding/json"
	"slices"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/sesv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
	"strings"
)

// Sending is a CloudTrail Data category, not management history. Content and
// recipient data never enter the shared diagnostic journal. Exact v2 field
// presence remains distinct from the published legacy SES CloudTrail examples.
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if isClassic(ctx) {
		return s.recordClassicCall(ctx, action, in, out, rejected)
	}
	if s.apiEvents == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("sesv2")
	op, _ := model.Operation(action)
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List"), Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
		"Content": {Mode: awsapi.OmitField}, "DefaultContent": {Mode: awsapi.OmitField}, "BulkEmailEntries": {Mode: awsapi.OmitField}, "TemplateContent": {Mode: awsapi.OmitField}, "TemplateData": {Mode: awsapi.OmitField}, "Destination": {Mode: awsapi.OmitField}, "ReplyToAddresses": {Mode: awsapi.OmitField}, "FeedbackForwardingEmailAddress": {Mode: awsapi.OmitField},
	}}}
	if action == "SendEmail" || action == "SendBulkEmail" {
		p.Category = journal.CategoryData
	}
	call, e := p.Call(model, op, in, out, rejected)
	if e != nil {
		return e
	}
	scope := scopeFor(ctx)
	if response, ok := out.(*api.SendEmailOutput); ok && response != nil && response.MessageId != nil {
		call.AdditionalEventData, e = json.Marshal(map[string]string{"sesMessageId": value(response.MessageId)})
		if e != nil {
			return e
		}
	}
	if p.Category == journal.CategoryData {
		var from, configuration string
		var template *api.Template
		switch v := in.(type) {
		case *api.SendEmailInput:
			from = value(v.FromEmailAddress)
			configuration = value(v.ConfigurationSetName)
			if v.Content != nil {
				template = v.Content.Template
			}
		case *api.SendBulkEmailInput:
			from = value(v.FromEmailAddress)
			configuration = value(v.ConfigurationSetName)
			if v.DefaultContent != nil {
				template = v.DefaultContent.Template
			}
		}
		if address, e := parseAddress(from); e == nil {
			call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: scope.AccountID, Type: "AWS::SES::EmailIdentity", ARN: ResourceKey{scope, address.Address}.ARN("identity")})
		}
		if configuration != "" {
			call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: scope.AccountID, Type: "AWS::SES::ConfigurationSet", ARN: ResourceKey{scope, configuration}.ARN("configuration-set")})
		}
		if template != nil {
			arn := value(template.TemplateArn)
			if template.TemplateName != nil {
				arn = ResourceKey{scope, value(template.TemplateName)}.ARN("template")
			}
			if arn != "" {
				call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: scope.AccountID, Type: "AWS::SES::Template", ARN: arn})
			}
		}
	}
	// Accepted rendered messages own resolved identities and inherited settings;
	// request-only projection would lose raw From and default configuration sets.
	if rejected == nil && p.Category == journal.CategoryData {
		ids := []string{}
		switch response := out.(type) {
		case *api.SendEmailOutput:
			if response != nil {
				ids = append(ids, value(response.MessageId))
			}
		case *api.SendBulkEmailOutput:
			if response != nil {
				for _, entry := range response.BulkEmailEntryResults {
					if entry.MessageId != nil {
						ids = append(ids, value(entry.MessageId))
					}
				}
			}
		}
		if len(ids) > 0 {
			call.EventResources, e = s.acceptedResources(ctx, scope, ids)
			if e != nil {
				return e
			}
		}
	}
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return s.recordCall(ctx, string(d.Operation.Name), d.Input, nil, e)
}

func (s *Service) acceptedResources(ctx context.Context, scope Scope, ids []string) ([]journal.APIEventResource, error) {
	var out []journal.APIEventResource
	err := s.repository.View(ctx, func(r Reader) error {
		resources := map[string]journal.APIEventResource{}
		for _, id := range ids {
			m, e := r.Message(ResourceKey{scope, id})
			if e != nil {
				return e
			}
			add := func(kind, typ, name string) {
				arn := ResourceKey{scope, name}.ARN(kind)
				resources[arn] = journal.APIEventResource{AccountID: scope.AccountID, Type: typ, ARN: arn}
			}
			if m.SourceIdentityARN != "" {
				parts := strings.SplitN(m.SourceIdentityARN, ":", 6)
				resources[m.SourceIdentityARN] = journal.APIEventResource{AccountID: parts[4], Type: "AWS::SES::EmailIdentity", ARN: m.SourceIdentityARN}
			} else if from, e := parseAddress(m.From); e == nil {
				add("identity", "AWS::SES::EmailIdentity", from.Address)
			}
			if m.ConfigurationSet != "" {
				add("configuration-set", "AWS::SES::ConfigurationSet", m.ConfigurationSet)
			}
			if m.TemplateName != "" {
				add("template", "AWS::SES::Template", m.TemplateName)
			}
		}
		keys := make([]string, 0, len(resources))
		for key := range resources {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			out = append(out, resources[key])
		}
		return nil
	})
	return out, err
}
