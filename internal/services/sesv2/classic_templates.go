package sesv2

import (
	classic "stackd/internal/awsapi/ses"
	api "stackd/internal/awsapi/sesv2"
)

func (c *ClassicService) registerTemplates() {
	registerClassic(c, "CreateTemplate", c.createTemplate)
	registerClassic(c, "UpdateTemplate", c.updateTemplate)
	registerClassic(c, "GetTemplate", c.getTemplate)
	registerClassic(c, "DeleteTemplate", c.deleteTemplate)
	registerClassic(c, "ListTemplates", c.listTemplates)
	registerClassic(c, "TestRenderTemplate", c.testRenderTemplate)
}
func classicTemplateContent(in *classic.Template) (*api.EmailTemplateContent, error) {
	if in == nil {
		return nil, bad("Template is required.")
	}
	return &api.EmailTemplateContent{Subject: (*api.EmailTemplateSubject)(in.SubjectPart), Text: (*api.EmailTemplateText)(in.TextPart), Html: (*api.EmailTemplateHtml)(in.HtmlPart)}, nil
}
func (c *ClassicService) createTemplate(tx Transaction, in *classic.CreateTemplateInput) (*classic.CreateTemplateOutput, error) {
	content, e := classicTemplateContent(in.Template)
	if e != nil {
		return nil, e
	}
	_, e = c.owner.createTemplate(tx, &api.CreateEmailTemplateInput{TemplateName: (*api.EmailTemplateName)(in.Template.TemplateName), TemplateContent: content})
	return &classic.CreateTemplateOutput{}, e
}
func (c *ClassicService) updateTemplate(tx Transaction, in *classic.UpdateTemplateInput) (*classic.UpdateTemplateOutput, error) {
	content, e := classicTemplateContent(in.Template)
	if e != nil {
		return nil, e
	}
	_, e = c.owner.updateTemplate(tx, &api.UpdateEmailTemplateInput{TemplateName: (*api.EmailTemplateName)(in.Template.TemplateName), TemplateContent: content})
	return &classic.UpdateTemplateOutput{}, e
}
func (c *ClassicService) getTemplate(tx Transaction, in *classic.GetTemplateInput) (*classic.GetTemplateOutput, error) {
	out, e := c.owner.getTemplate(tx, &api.GetEmailTemplateInput{TemplateName: (*api.EmailTemplateName)(in.TemplateName)})
	if e != nil {
		return nil, e
	}
	return &classic.GetTemplateOutput{Template: &classic.Template{TemplateName: (*classic.TemplateName)(out.TemplateName), SubjectPart: (*classic.SubjectPart)(out.TemplateContent.Subject), TextPart: (*classic.TextPart)(out.TemplateContent.Text), HtmlPart: (*classic.HtmlPart)(out.TemplateContent.Html)}}, nil
}
func (c *ClassicService) deleteTemplate(tx Transaction, in *classic.DeleteTemplateInput) (*classic.DeleteTemplateOutput, error) {
	_, e := c.owner.deleteTemplate(tx, &api.DeleteEmailTemplateInput{TemplateName: (*api.EmailTemplateName)(in.TemplateName)})
	return &classic.DeleteTemplateOutput{}, e
}
func (c *ClassicService) listTemplates(tx Transaction, in *classic.ListTemplatesInput) (*classic.ListTemplatesOutput, error) {
	out, e := c.owner.listTemplates(tx, &api.ListEmailTemplatesInput{NextToken: (*api.NextToken)(in.NextToken), PageSize: (*api.MaxItems)(in.MaxItems)})
	if e != nil {
		return nil, e
	}
	v := &classic.ListTemplatesOutput{NextToken: (*classic.NextToken)(out.NextToken), TemplatesMetadata: make(classic.TemplateMetadataList, 0, len(out.TemplatesMetadata))}
	for _, t := range out.TemplatesMetadata {
		v.TemplatesMetadata = append(v.TemplatesMetadata, classic.TemplateMetadata{Name: (*classic.TemplateName)(t.TemplateName), CreatedTimestamp: t.CreatedTimestamp})
	}
	return v, nil
}
func (c *ClassicService) testRenderTemplate(tx Transaction, in *classic.TestRenderTemplateInput) (*classic.TestRenderTemplateOutput, error) {
	out, e := c.owner.testRenderTemplate(tx, &api.TestRenderEmailTemplateInput{TemplateName: (*api.EmailTemplateName)(in.TemplateName), TemplateData: (*api.EmailTemplateData)(in.TemplateData)})
	if e != nil {
		return nil, e
	}
	return &classic.TestRenderTemplateOutput{RenderedTemplate: (*classic.RenderedTemplate)(out.RenderedTemplate)}, nil
}
