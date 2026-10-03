package sesv2

import (
	"encoding/json"
	"errors"
	"regexp"
	api "stackd/internal/awsapi/sesv2"
	"strings"
)

var templateVariable = regexp.MustCompile(`\{\{\{?\s*([A-Za-z0-9_.-]+)\s*\}\}\}?`)

func validateTemplate(t Template) error {
	if t.Subject == "" || (t.Text == "" && t.HTML == "") {
		return bad("Template must include a subject and at least one body.")
	}
	for _, v := range []string{t.Subject, t.Text, t.HTML} {
		remaining := templateVariable.ReplaceAllString(v, "")
		if strings.Contains(remaining, "{{") || strings.Contains(remaining, "}}") {
			// TODO: Comeback — stored-template Handlebars blocks, helpers and partials require full compatible evaluation; never send their unevaluated source.
			return unsupported("Only simple template substitutions and nested object paths are implemented.")
		}
	}
	return nil
}

// SES intentionally performs no automatic HTML escaping; applications own escaping.
func renderPart(source string, data map[string]any) (string, error) {
	var failure error
	out := templateVariable.ReplaceAllStringFunc(source, func(token string) string {
		match := templateVariable.FindStringSubmatch(token)
		var v any = data
		for _, part := range strings.Split(match[1], ".") {
			object, ok := v.(map[string]any)
			if !ok {
				failure = bad("Missing template attribute: " + match[1])
				return ""
			}
			v, ok = object[part]
			if !ok {
				failure = bad("Missing template attribute: " + match[1])
				return ""
			}
		}
		text, ok := v.(string)
		if !ok {
			if v == nil {
				text = ""
			} else {
				b, e := json.Marshal(v)
				if e != nil {
					failure = e
				}
				text = string(b)
			}
		}
		return text
	})
	return out, failure
}
func renderTemplate(t Template, raw string) (Template, error) {
	if e := validateTemplate(t); e != nil {
		return t, e
	}
	if raw == "" {
		raw = "{}"
	}
	var data map[string]any
	if e := json.Unmarshal([]byte(raw), &data); e != nil || data == nil {
		return t, bad("TemplateData must be a JSON object.")
	}
	var e error
	t.Subject, e = renderPart(t.Subject, data)
	if e != nil {
		return t, e
	}
	t.Text, e = renderPart(t.Text, data)
	if e != nil {
		return t, e
	}
	t.HTML, e = renderPart(t.HTML, data)
	return t, e
}
func templateContent(k ResourceKey, in *api.EmailTemplateContent) (Template, error) {
	if in == nil {
		return Template{}, bad("TemplateContent is required.")
	}
	t := Template{Key: k, Subject: value(in.Subject), Text: value(in.Text), HTML: value(in.Html)}
	return t, validateTemplate(t)
}
func (s *Service) createTemplate(tx Transaction, in *api.CreateEmailTemplateInput) (*api.CreateEmailTemplateOutput, error) {
	if len(in.Tags) > 0 {
		return nil, unsupported("Email template resource tags are not implemented.")
	}
	k := ResourceKey{scopeFor(tx.Context()), value(in.TemplateName)}
	if !resourceName.MatchString(k.Name) {
		return nil, bad("Invalid template name.")
	}
	if e := s.authorize(tx, "CreateEmailTemplate", k.ARN("template"), nil, nil); e != nil {
		return nil, e
	}
	if _, e := tx.Template(k); e == nil {
		return nil, failure("AlreadyExistsException", "Template already exists.", 400)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	t, e := templateContent(k, in.TemplateContent)
	if e != nil {
		return nil, e
	}
	t.Created = s.clock.Now()
	return &api.CreateEmailTemplateOutput{}, tx.PutTemplate(t)
}
func (s *Service) updateTemplate(tx Transaction, in *api.UpdateEmailTemplateInput) (*api.UpdateEmailTemplateOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.TemplateName)}
	if e := s.authorize(tx, "UpdateEmailTemplate", k.ARN("template"), nil, nil); e != nil {
		return nil, e
	}
	old, e := tx.Template(k)
	if e != nil {
		return nil, e
	}
	t, e := templateContent(k, in.TemplateContent)
	if e != nil {
		return nil, e
	}
	t.Created = old.Created
	return &api.UpdateEmailTemplateOutput{}, tx.PutTemplate(t)
}
func (s *Service) getTemplate(tx Transaction, in *api.GetEmailTemplateInput) (*api.GetEmailTemplateOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.TemplateName)}
	if e := s.authorize(tx, "GetEmailTemplate", k.ARN("template"), nil, nil); e != nil {
		return nil, e
	}
	v, e := tx.Template(k)
	if e != nil {
		return nil, e
	}
	return &api.GetEmailTemplateOutput{TemplateName: new(api.EmailTemplateName(k.Name)), TemplateContent: &api.EmailTemplateContent{Subject: new(api.EmailTemplateSubject(v.Subject)), Text: new(api.EmailTemplateText(v.Text)), Html: new(api.EmailTemplateHtml(v.HTML))}}, nil
}
func (s *Service) deleteTemplate(tx Transaction, in *api.DeleteEmailTemplateInput) (*api.DeleteEmailTemplateOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.TemplateName)}
	if e := s.authorize(tx, "DeleteEmailTemplate", k.ARN("template"), nil, nil); e != nil {
		return nil, e
	}
	return &api.DeleteEmailTemplateOutput{}, tx.DeleteTemplate(k)
}
func (s *Service) listTemplates(tx Transaction, in *api.ListEmailTemplatesInput) (*api.ListEmailTemplatesOutput, error) {
	if e := s.authorize(tx, "ListEmailTemplates", "*", nil, nil); e != nil {
		return nil, e
	}
	rows, e := tx.Templates(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	start, end, next, e := page(rows, scopeFor(tx.Context()), "templates", "", in.NextToken, in.PageSize, func(v Template) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.ListEmailTemplatesOutput{TemplatesMetadata: api.EmailTemplateMetadataList{}, NextToken: next}
	for _, v := range rows[start:end] {
		out.TemplatesMetadata = append(out.TemplatesMetadata, api.EmailTemplateMetadata{TemplateName: new(api.EmailTemplateName(v.Key.Name)), CreatedTimestamp: new(v.Created)})
	}
	return out, nil
}
func (s *Service) testRenderTemplate(tx Transaction, in *api.TestRenderEmailTemplateInput) (*api.TestRenderEmailTemplateOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.TemplateName)}
	if e := s.authorize(tx, "TestRenderEmailTemplate", k.ARN("template"), nil, nil); e != nil {
		return nil, e
	}
	v, e := tx.Template(k)
	if e != nil {
		return nil, e
	}
	v, e = renderTemplate(v, value(in.TemplateData))
	if e != nil {
		return nil, e
	}
	m := Message{Subject: v.Subject, Text: v.Text, HTML: v.HTML, Accepted: s.clock.Now()}
	body, e := renderMIME(m, nil)
	if e != nil {
		return nil, e
	}
	return &api.TestRenderEmailTemplateOutput{RenderedTemplate: new(api.RenderedEmailTemplate(string(body)))}, nil
}
func resolveTemplate(tx Reader, scope Scope, in *api.Template) (Template, error) {
	count := 0
	if in.TemplateName != nil {
		count++
	}
	if in.TemplateArn != nil {
		count++
	}
	if in.TemplateContent != nil {
		count++
	}
	if count != 1 {
		return Template{}, bad("Specify exactly one template name, ARN, or inline content.")
	}
	if in.TemplateContent != nil {
		return templateContent(ResourceKey{Scope: scope}, in.TemplateContent)
	}
	name := value(in.TemplateName)
	if in.TemplateArn != nil {
		prefix := ResourceKey{Scope: scope}.ARN("template")
		if !strings.HasPrefix(value(in.TemplateArn), prefix) {
			return Template{}, ErrNotFound
		}
		name = strings.TrimPrefix(value(in.TemplateArn), prefix)
	}
	return tx.Template(ResourceKey{scope, name})
}
