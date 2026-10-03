package sesv2

import (
	"encoding/json"
	"errors"
	classic "stackd/internal/awsapi/ses"
	api "stackd/internal/awsapi/sesv2"
)

func (c *ClassicService) registerSending() {
	registerClassic(c, "SendEmail", c.sendEmail)
	registerClassic(c, "SendRawEmail", c.sendRawEmail)
	registerClassic(c, "SendTemplatedEmail", c.sendTemplatedEmail)
	registerClassic(c, "SendBulkTemplatedEmail", c.sendBulkTemplatedEmail)
}
func convertStrings[A, B ~string](in []A) []B {
	if in == nil {
		return nil
	}
	out := make([]B, len(in))
	for i, v := range in {
		out[i] = B(v)
	}
	return out
}
func classicDestination(in *classic.Destination) *api.Destination {
	if in == nil {
		return nil
	}
	return &api.Destination{ToAddresses: convertStrings[classic.Address, api.EmailAddress](in.ToAddresses), CcAddresses: convertStrings[classic.Address, api.EmailAddress](in.CcAddresses), BccAddresses: convertStrings[classic.Address, api.EmailAddress](in.BccAddresses)}
}
func classicContent(in *classic.Content) *api.Content {
	if in == nil {
		return nil
	}
	return &api.Content{Data: (*api.MessageData)(in.Data), Charset: (*api.Charset)(in.Charset)}
}
func classicTags(in classic.MessageTagList) api.MessageTagList {
	if in == nil {
		return nil
	}
	out := make(api.MessageTagList, len(in))
	for i, v := range in {
		out[i] = api.MessageTag{Name: (*api.MessageTagName)(v.Name), Value: (*api.MessageTagValue)(v.Value)}
	}
	return out
}
func (c *ClassicService) sendEmail(tx Transaction, in *classic.SendEmailInput) (*classic.SendEmailOutput, error) {
	if in.Message == nil || in.Message.Body == nil || in.Message.Body.Text == nil && in.Message.Body.Html == nil {
		return nil, failure("ValidationError", "1 validation error detected: Value at 'message.body' failed to satisfy constraint: Member must not be null", 400)
	}
	v := &api.SendEmailInput{FromEmailAddress: (*api.EmailAddress)(in.Source), FromEmailAddressIdentityArn: (*api.AmazonResourceName)(in.SourceArn), FeedbackForwardingEmailAddress: (*api.EmailAddress)(in.ReturnPath), FeedbackForwardingEmailAddressIdentityArn: (*api.AmazonResourceName)(in.ReturnPathArn), ConfigurationSetName: (*api.ConfigurationSetName)(in.ConfigurationSetName), Destination: classicDestination(in.Destination), ReplyToAddresses: convertStrings[classic.Address, api.EmailAddress](in.ReplyToAddresses), EmailTags: classicTags(in.Tags), Content: &api.EmailContent{Simple: &api.Message{Subject: classicContent(in.Message.Subject), Body: &api.Body{Text: classicContent(in.Message.Body.Text), Html: classicContent(in.Message.Body.Html)}}}}
	out, e := c.owner.sendEmail(tx, v)
	if e != nil {
		return nil, e
	}
	return &classic.SendEmailOutput{MessageId: (*classic.MessageId)(out.MessageId)}, nil
}
func (c *ClassicService) sendRawEmail(tx Transaction, in *classic.SendRawEmailInput) (*classic.SendRawEmailOutput, error) {
	if in.RawMessage == nil {
		return nil, bad("RawMessage is required.")
	}
	v := &api.SendEmailInput{FromEmailAddress: (*api.EmailAddress)(in.Source), FromEmailAddressIdentityArn: (*api.AmazonResourceName)(in.SourceArn), FeedbackForwardingEmailAddressIdentityArn: (*api.AmazonResourceName)(in.ReturnPathArn), ConfigurationSetName: (*api.ConfigurationSetName)(in.ConfigurationSetName), EmailTags: classicTags(in.Tags), Content: &api.EmailContent{Raw: &api.RawMessage{Data: api.RawMessageData(in.RawMessage.Data)}}}
	if len(in.Destinations) > 0 {
		v.Destination = &api.Destination{ToAddresses: convertStrings[classic.Address, api.EmailAddress](in.Destinations)}
	}
	m, e := c.owner.prepareWithOptions(tx, v, "SendRawEmail", sendOptions{RawFromARN: value(in.FromArn)})
	if e != nil {
		return nil, e
	}
	if e = tx.PutMessage(m); e != nil {
		return nil, e
	}
	return &classic.SendRawEmailOutput{MessageId: new(classic.MessageId(m.Key.Name))}, nil
}
func classicSendTemplate(name *classic.TemplateName, arn *classic.AmazonResourceName, data *classic.TemplateData) *api.Template {
	t := &api.Template{TemplateName: (*api.EmailTemplateName)(name), TemplateData: (*api.EmailTemplateData)(data)}
	if arn != nil {
		t.TemplateName = nil
		t.TemplateArn = (*api.AmazonResourceName)(arn)
	}
	return t
}
func (c *ClassicService) sendTemplatedEmail(tx Transaction, in *classic.SendTemplatedEmailInput) (*classic.SendTemplatedEmailOutput, error) {
	if !json.Valid([]byte(value(in.TemplateData))) {
		return nil, bad("Unable to parse template data (invalid JSON).")
	}
	out, e := c.owner.sendEmail(tx, &api.SendEmailInput{FromEmailAddress: (*api.EmailAddress)(in.Source), FromEmailAddressIdentityArn: (*api.AmazonResourceName)(in.SourceArn), FeedbackForwardingEmailAddress: (*api.EmailAddress)(in.ReturnPath), FeedbackForwardingEmailAddressIdentityArn: (*api.AmazonResourceName)(in.ReturnPathArn), ConfigurationSetName: (*api.ConfigurationSetName)(in.ConfigurationSetName), Destination: classicDestination(in.Destination), ReplyToAddresses: convertStrings[classic.Address, api.EmailAddress](in.ReplyToAddresses), EmailTags: classicTags(in.Tags), Content: &api.EmailContent{Template: classicSendTemplate(in.Template, in.TemplateArn, in.TemplateData)}})
	if e != nil {
		return nil, e
	}
	return &classic.SendTemplatedEmailOutput{MessageId: (*classic.MessageId)(out.MessageId)}, nil
}
func (c *ClassicService) sendBulkTemplatedEmail(tx Transaction, in *classic.SendBulkTemplatedEmailInput) (*classic.SendBulkTemplatedEmailOutput, error) {
	if len(in.Destinations) < 1 || len(in.Destinations) > 50 {
		return nil, bad("Bulk email requires between 1 and 50 entries.")
	}
	from, e := parseAddress(value(in.Source))
	if e != nil {
		return nil, e
	}
	conditions := map[string][]string{"ses:FromAddress": {from.Address}, "ses:FromDisplayName": {from.Name}}
	for _, d := range in.Destinations {
		if d.Destination == nil {
			return nil, bad("Destination is required.")
		}
		for _, list := range []classic.AddressList{d.Destination.ToAddresses, d.Destination.CcAddresses, d.Destination.BccAddresses} {
			for _, raw := range list {
				a, e := parseAddress(string(raw))
				if e != nil {
					return nil, e
				}
				conditions["ses:Recipients"] = append(conditions["ses:Recipients"], a.Address)
			}
		}
	}
	if in.ReturnPath != nil {
		a, e := parseAddress(value(in.ReturnPath))
		if e != nil {
			return nil, e
		}
		conditions["ses:FeedbackAddress"] = []string{a.Address}
	}
	if _, e = c.owner.admitSource(tx, "SendBulkTemplatedEmail", scopeFor(tx.Context()), from, value(in.SourceArn), conditions); e != nil {
		return nil, e
	}
	if e = classicConfigurationExists(tx, value(in.ConfigurationSetName)); e != nil {
		return nil, e
	}
	if _, e = resolveTemplate(tx, scopeFor(tx.Context()), classicSendTemplate(in.Template, in.TemplateArn, in.DefaultTemplateData)); e != nil {
		return nil, e
	}
	v := &api.SendBulkEmailInput{FromEmailAddress: (*api.EmailAddress)(in.Source), FromEmailAddressIdentityArn: (*api.AmazonResourceName)(in.SourceArn), FeedbackForwardingEmailAddress: (*api.EmailAddress)(in.ReturnPath), FeedbackForwardingEmailAddressIdentityArn: (*api.AmazonResourceName)(in.ReturnPathArn), ConfigurationSetName: (*api.ConfigurationSetName)(in.ConfigurationSetName), ReplyToAddresses: convertStrings[classic.Address, api.EmailAddress](in.ReplyToAddresses), DefaultEmailTags: classicTags(in.DefaultTags), DefaultContent: &api.BulkEmailContent{Template: classicSendTemplate(in.Template, in.TemplateArn, in.DefaultTemplateData)}, BulkEmailEntries: make(api.BulkEmailEntryList, len(in.Destinations))}
	for i, d := range in.Destinations {
		v.BulkEmailEntries[i] = api.BulkEmailEntry{Destination: classicDestination(d.Destination), ReplacementTags: classicTags(d.ReplacementTags)}
		if d.ReplacementTemplateData != nil {
			v.BulkEmailEntries[i].ReplacementEmailContent = &api.ReplacementEmailContent{ReplacementTemplate: &api.ReplacementTemplate{ReplacementTemplateData: (*api.EmailTemplateData)(d.ReplacementTemplateData)}}
		}
	}
	out, e := c.owner.sendBulkEmail(tx, v)
	if e != nil {
		return nil, e
	}
	result := &classic.SendBulkTemplatedEmailOutput{Status: make(classic.BulkEmailDestinationStatusList, len(out.BulkEmailEntryResults))}
	for i, v := range out.BulkEmailEntryResults {
		status := classic.BulkEmailStatusFailed
		switch value(v.Status) {
		case "SUCCESS":
			status = classic.BulkEmailStatusSuccess
		case "MESSAGE_REJECTED":
			status = classic.BulkEmailStatusMessageRejected
		case "ACCOUNT_SUSPENDED":
			status = classic.BulkEmailStatusAccountSuspended
		case "ACCOUNT_THROTTLED":
			status = classic.BulkEmailStatusAccountThrottled
		case "ACCOUNT_DAILY_QUOTA_EXCEEDED":
			status = classic.BulkEmailStatusAccountDailyQuotaExceeded
		case "CONFIGURATION_SET_NOT_FOUND":
			status = classic.BulkEmailStatusConfigurationSetDoesNotExist
		case "TEMPLATE_NOT_FOUND":
			status = classic.BulkEmailStatusTemplateDoesNotExist
		case "ACCOUNT_SENDING_PAUSED":
			status = classic.BulkEmailStatusAccountSendingPaused
		}
		result.Status[i] = classic.BulkEmailDestinationStatus{Status: &status, MessageId: (*classic.MessageId)(v.MessageId), Error: (*classic.Error)(v.Error)}
	}
	return result, nil
}

func classicConfigurationExists(tx Reader, name string) error {
	if name == "" {
		return nil
	}
	config, e := tx.ConfigurationSet(ResourceKey{scopeFor(tx.Context()), name})
	if errors.Is(e, ErrNotFound) {
		return failure("ConfigurationSetDoesNotExist", "Configuration set <"+name+"> does not exist.", 400)
	}
	if e == nil && !config.SendingEnabled {
		return failure("ConfigurationSetSendingPaused", "Sending is disabled for this configuration set.", 400)
	}
	return e
}
