package sesv2

import (
	"errors"
	"maps"
	"net/mail"
	api "stackd/internal/awsapi/sesv2"
	"stackd/internal/awswire"
	"strings"
)

func (s *Service) registerSending() {
	register(s, "SendEmail", s.sendEmail)
	register(s, "SendBulkEmail", s.sendBulkEmail)
}
func messageTags(tags api.MessageTagList) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range tags {
		k, val := value(v.Name), value(v.Value)
		if k == "" || len(k) > 256 || len(val) > 256 {
			return nil, bad("Invalid message tag.")
		}
		out[k] = val
	}
	return out, nil
}
func (s *Service) sendEmail(tx Transaction, in *api.SendEmailInput) (*api.SendEmailOutput, error) {
	m, e := s.prepare(tx, in, "SendEmail")
	if e != nil {
		return nil, e
	}
	if e = tx.PutMessage(m); e != nil {
		return nil, e
	}
	return &api.SendEmailOutput{MessageId: new(api.OutboundMessageId(m.Key.Name))}, nil
}
func (s *Service) prepare(tx Transaction, in *api.SendEmailInput, action string) (Message, error) {
	return s.prepareWithOptions(tx, in, action, sendOptions{})
}

type sendOptions struct {
	RawFromARN string
}

func (s *Service) prepareWithOptions(tx Transaction, in *api.SendEmailInput, action string, options sendOptions) (Message, error) {
	var m Message
	m.Key.Scope = scopeFor(tx.Context())
	m.From = value(in.FromEmailAddress)
	m.Feedback = value(in.FeedbackForwardingEmailAddress)
	m.ConfigurationSet = value(in.ConfigurationSetName)
	if in.EndpointId != nil || in.TenantName != nil || in.ListManagementOptions != nil || in.ConfigurationOverrides != nil {
		return m, unsupported("Global endpoints, tenants, list management and configuration overrides are not implemented.")
	}
	sourceARN := value(in.FromEmailAddressIdentityArn)
	feedbackARN := value(in.FeedbackForwardingEmailAddressIdentityArn)
	if in.Content == nil {
		return m, bad("Content is required.")
	}
	count := 0
	if in.Content.Simple != nil {
		count++
	}
	if in.Content.Raw != nil {
		count++
	}
	if in.Content.Template != nil {
		count++
	}
	if count != 1 {
		return m, bad("Specify exactly one Simple, Raw or Template content.")
	}
	var e error
	if in.Destination != nil {
		m.To, e = addressList(in.Destination.ToAddresses)
		if e != nil {
			return m, e
		}
		m.CC, e = addressList(in.Destination.CcAddresses)
		if e != nil {
			return m, e
		}
		m.BCC, e = addressList(in.Destination.BccAddresses)
		if e != nil {
			return m, e
		}
	}
	m.ReplyTo, e = addressList(in.ReplyToAddresses)
	if e != nil {
		return m, e
	}
	m.Tags, e = messageTags(in.EmailTags)
	if e != nil {
		return m, e
	}
	var rawHeaders mail.Header
	var rawBody []byte
	simple := in.Content.Simple
	if simple != nil {
		m.ContentKind = "SIMPLE"
		if simple.Body == nil || simple.Body.Text == nil && simple.Body.Html == nil {
			return m, bad("Value null at both body.text and body.html.")
		}
		m.Subject, e = contentText(simple.Subject)
		if e != nil {
			return m, e
		}
		if simple.Body.Text != nil {
			m.Text, e = contentText(simple.Body.Text)
			if e != nil {
				return m, e
			}
		}
		if simple.Body.Html != nil {
			m.HTML, e = contentText(simple.Body.Html)
			if e != nil {
				return m, e
			}
		}
	}
	if in.Content.Raw != nil {
		m.ContentKind = "RAW"
		rawHeaders, rawBody, e = parseRaw(&m, in.Content.Raw.Data)
		if e != nil {
			return m, e
		}
		if sourceARN == "" {
			sourceARN = rawHeaders.Get("X-SES-SOURCE-ARN")
		}
		if options.RawFromARN == "" {
			options.RawFromARN = rawHeaders.Get("X-SES-FROM-ARN")
		}
		if feedbackARN == "" {
			feedbackARN = rawHeaders.Get("X-SES-RETURN-PATH-ARN")
		}
		if m.Feedback == "" {
			m.Feedback = rawHeaders.Get("Return-Path")
		}
	}
	from, e := parseAddress(m.From)
	if e != nil {
		return m, e
	}
	m.From = from.String()
	if len(m.To)+len(m.CC)+len(m.BCC) < 1 || len(m.To)+len(m.CC)+len(m.BCC) > 50 {
		return m, bad("Messages require 1 to 50 recipients.")
	}
	if isClassic(tx.Context()) {
		if e = classicConfigurationExists(tx, m.ConfigurationSet); e != nil {
			return m, e
		}
	}
	conditions := map[string][]string{"ses:FromAddress": {from.Address}, "ses:FromDisplayName": {from.Name}}
	for _, addresses := range [][]string{m.To, m.CC, m.BCC} {
		for _, v := range addresses {
			a, _ := parseAddress(v)
			conditions["ses:Recipients"] = append(conditions["ses:Recipients"], a.Address)
		}
	}
	if m.Feedback != "" {
		a, e := parseAddress(m.Feedback)
		if e != nil {
			return m, e
		}
		conditions["ses:FeedbackAddress"] = []string{a.Address}
	}
	identity, e := s.admitSource(tx, action, m.Key.Scope, from, sourceARN, conditions)
	if e != nil {
		return m, e
	}
	m.SourceIdentityARN = identity.Key.ARN("identity")
	if rawHeaders != nil {
		rawFrom, _ := parseAddress(rawHeaders.Get("From"))
		if rawFrom.Address != from.Address || options.RawFromARN != "" {
			rawIdentity, arn, e := s.resolveSendingIdentity(tx, rawFrom.Address, options.RawFromARN)
			if e != nil {
				return m, e
			}
			if e = s.authorizeSendingIdentity(tx, action, arn, rawIdentity, conditions); e != nil {
				return m, e
			}
			if !rawIdentity.Verified {
				return m, rejectedIdentity(rawFrom.Address, m.Key.Region)
			}
		}
	}
	for _, address := range conditions["ses:Recipients"] {
		if e = s.requireVerified(tx, m.Key.Scope, address, true); e != nil {
			return m, e
		}
	}
	if m.Feedback != "" {
		a, _ := parseAddress(m.Feedback)
		feedbackIdentity, arn, e := s.resolveSendingIdentity(tx, a.Address, feedbackARN)
		if e != nil {
			return m, e
		}
		if feedbackARN != "" {
			if e = s.authorizeSendingIdentity(tx, action, arn, feedbackIdentity, conditions); e != nil {
				return m, e
			}
		}
		if !feedbackIdentity.Verified {
			return m, rejectedIdentity(a.Address, m.Key.Region)
		}
	}
	if m.ConfigurationSet == "" {
		m.ConfigurationSet = identity.ConfigurationSet
	}
	if m.ConfigurationSet != "" {
		config, e := tx.ConfigurationSet(ResourceKey{m.Key.Scope, m.ConfigurationSet})
		if e != nil {
			return m, e
		}
		if e = s.authorize(tx, action, config.Key.ARN("configuration-set"), config.Tags, conditions); e != nil {
			return m, e
		}
		if !config.SendingEnabled {
			return m, failure("SendingPausedException", "Sending is disabled for this configuration set.", 400)
		}
	}
	if t := in.Content.Template; t != nil {
		m.ContentKind = "TEMPLATE"
		v, e := resolveTemplate(tx, m.Key.Scope, t)
		if e != nil {
			return m, e
		}
		if v.Key.Name != "" {
			if e = s.authorize(tx, action, v.Key.ARN("template"), nil, conditions); e != nil {
				return m, e
			}
		}
		m.TemplateName = v.Key.Name
		m.TemplateData = value(t.TemplateData)
		v, e = renderTemplate(v, m.TemplateData)
		if e != nil {
			return m, e
		}
		m.Subject, m.Text, m.HTML = v.Subject, v.Text, v.HTML
		simple = &api.Message{Headers: t.Headers, Attachments: t.Attachments}
	}
	m.Key.Name, e = newID()
	if e != nil {
		return m, e
	}
	m.Accepted = s.clock.Now().UTC()
	m.Due = m.Accepted
	m.CapturePending = true
	if rawHeaders != nil {
		m.MIME, e = finalizeRaw(m, rawHeaders, rawBody)
	} else {
		m.MIME, e = renderMIME(m, simple)
	}
	if e == nil && isClassic(tx.Context()) && len(m.MIME) > 10*1024*1024 {
		return m, bad("Message exceeds 10 MB.")
	}
	return m, e
}

func (s *Service) admitSource(tx Transaction, action string, scope Scope, from *mail.Address, sourceARN string, conditions map[string][]string) (Identity, error) {
	identity, arn, e := s.resolveSendingIdentity(tx, from.Address, sourceARN)
	if e != nil {
		return identity, e
	}
	if e = s.authorizeSendingIdentity(tx, action, arn, identity, conditions); e != nil {
		return identity, e
	}
	if !identity.Verified {
		return identity, rejectedIdentity(from.Address, scope.Region)
	}
	account, e := tx.Account(scope)
	if e != nil {
		return identity, e
	}
	if !account.SendingEnabled {
		return identity, failure("SendingPausedException", "Email sending is disabled for this account.", 400)
	}
	return identity, nil
}
func rejectedIdentity(address, region string) *awswire.Error {
	return failure("MessageRejected", "Email address is not verified. The following identities failed the check in region "+strings.ToUpper(region)+": "+address, 400)
}
func (s *Service) requireVerified(tx Reader, scope Scope, address string, recipient bool) error {
	if recipient && simulatorRecipient(address) {
		return nil
	}
	v, e := tx.Identity(ResourceKey{scope, address})
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if !v.Verified {
		return rejectedIdentity(address, scope.Region)
	}
	return nil
}
func simulatorRecipient(address string) bool {
	local, domain, ok := strings.Cut(strings.ToLower(address), "@")
	if !ok || domain != "simulator.amazonses.com" {
		return false
	}
	local, _, _ = strings.Cut(local, "+")
	switch local {
	case "success", "bounce", "complaint", "ooto", "suppressionlist":
		return true
	}
	return false
}

// acceptManaged is reserved for SES verification and AWS-managed Cognito default
// mail, not an IAM request path. Both still durably retain a real MIME artifact.
func (s *Service) acceptManaged(tx Transaction, scope Scope, from, to, subject, text, kind string) (Message, error) {
	id, e := newID()
	if e != nil {
		return Message{}, e
	}
	sender, e := parseAddress(from)
	if e != nil {
		return Message{}, e
	}
	recipient, e := parseAddress(to)
	if e != nil {
		return Message{}, e
	}
	now := s.clock.Now().UTC()
	m := Message{Key: ResourceKey{scope, id}, From: sender.String(), To: []string{recipient.String()}, Subject: subject, Text: text, ContentKind: kind, Accepted: now, Due: now, CapturePending: true, Tags: map[string]string{}}
	m.MIME, e = renderMIME(m, nil)
	if e != nil {
		return m, e
	}
	return m, tx.PutMessage(m)
}
func (s *Service) sendBulkEmail(tx Transaction, in *api.SendBulkEmailInput) (*api.SendBulkEmailOutput, error) {
	if len(in.BulkEmailEntries) < 1 || len(in.BulkEmailEntries) > 50 {
		return nil, bad("Bulk email requires between 1 and 50 entries.")
	}
	if in.DefaultContent == nil || in.DefaultContent.Template == nil {
		return nil, bad("Default template content is required.")
	}
	out := &api.SendBulkEmailOutput{BulkEmailEntryResults: api.BulkEmailEntryResultList{}}
	for _, entry := range in.BulkEmailEntries {
		t := *in.DefaultContent.Template
		if replacement := entry.ReplacementEmailContent; replacement != nil && replacement.ReplacementTemplate != nil {
			t.TemplateData = replacement.ReplacementTemplate.ReplacementTemplateData
		}
		t.Headers = mergeHeaders(t.Headers, entry.ReplacementHeaders)
		tags := in.DefaultEmailTags
		if len(entry.ReplacementTags) > 0 {
			base, e := messageTags(tags)
			if e != nil {
				return nil, e
			}
			replace, e := messageTags(entry.ReplacementTags)
			if e != nil {
				return nil, e
			}
			maps.Copy(base, replace)
			tags = nil
			for k, v := range base {
				tags = append(tags, api.MessageTag{Name: new(api.MessageTagName(k)), Value: new(api.MessageTagValue(v))})
			}
		}
		single := &api.SendEmailInput{FromEmailAddress: in.FromEmailAddress, FromEmailAddressIdentityArn: in.FromEmailAddressIdentityArn, Destination: entry.Destination, ReplyToAddresses: in.ReplyToAddresses, FeedbackForwardingEmailAddress: in.FeedbackForwardingEmailAddress, FeedbackForwardingEmailAddressIdentityArn: in.FeedbackForwardingEmailAddressIdentityArn, Content: &api.EmailContent{Template: &t}, EmailTags: tags, ConfigurationSetName: in.ConfigurationSetName, EndpointId: in.EndpointId, TenantName: in.TenantName, ConfigurationOverrides: in.ConfigurationOverrides}
		m, e := s.prepare(tx, single, "SendBulkEmail")
		if e != nil {
			wire := wireError(e)
			if wire.Code == "NotImplementedException" || wire.Code == "AccessDeniedException" || wire.StatusCode >= 500 {
				return nil, e
			}
			status := "FAILED"
			switch wire.Code {
			case "MessageRejected":
				status = "MESSAGE_REJECTED"
			case "NotFoundException":
				status = "TEMPLATE_NOT_FOUND"
			case "SendingPausedException":
				status = "ACCOUNT_SENDING_PAUSED"
			}
			out.BulkEmailEntryResults = append(out.BulkEmailEntryResults, api.BulkEmailEntryResult{Status: new(api.BulkEmailStatus(status)), Error: new(api.ErrorMessage(wire.Message))})
			continue
		}
		if e = tx.PutMessage(m); e != nil {
			return nil, e
		}
		out.BulkEmailEntryResults = append(out.BulkEmailEntryResults, api.BulkEmailEntryResult{Status: new(api.BulkEmailStatus("SUCCESS")), MessageId: new(api.OutboundMessageId(m.Key.Name))})
	}
	return out, nil
}
func mergeHeaders(base, replacements api.MessageHeaderList) api.MessageHeaderList {
	out := append(api.MessageHeaderList(nil), base...)
	for _, h := range replacements {
		found := false
		for i, v := range out {
			if strings.EqualFold(value(h.Name), value(v.Name)) {
				out[i] = h
				found = true
				break
			}
		}
		if !found {
			out = append(out, h)
		}
	}
	return out
}
