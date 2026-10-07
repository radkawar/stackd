package integrations

import (
	"context"
	"fmt"

	sesapi "stackd/internal/awsapi/sesv2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sesv2"
)

// AWS::SES::Template
// Contract: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-template.html
// Wire: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateEmailTemplate.html
// SES templates are untaggable in the owner, so the incarnation claim is an
// internal SES template owner field rather than a tag.
type cfnSESTemplate struct{ commands StepFunctionsCommands }

func (cfnSESTemplate) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Template", "Tags"); err != nil {
		return err
	}
	if cfnTrustPresent(p, "Tags") {
		return fmt.Errorf("SES template tags have no owner")
	}
	_, err := cfnSESTemplateContent(p)
	return err
}
func cfnSESTemplateObject(p map[string]any) (map[string]any, error) {
	if p["Template"] == nil {
		return nil, fmt.Errorf("Template is required")
	}
	template, ok := cfnComputeObject(p["Template"])
	if !ok {
		return nil, fmt.Errorf("Template must be an object")
	}
	if err := cfnComputeProperties(template, "TemplateName", "SubjectPart", "TextPart", "HtmlPart"); err != nil {
		return nil, fmt.Errorf("Template: %w", err)
	}
	if err := cfnComputeRequired(template, "SubjectPart"); err != nil {
		return nil, fmt.Errorf("Template: %w", err)
	}
	if err := cfnComputeStrings(template, "TemplateName", "SubjectPart", "TextPart", "HtmlPart"); err != nil {
		return nil, fmt.Errorf("Template: %w", err)
	}
	return template, nil
}
func cfnSESTemplateContent(p map[string]any) (*sesapi.EmailTemplateContent, error) {
	template, err := cfnSESTemplateObject(p)
	if err != nil {
		return nil, err
	}
	content := &sesapi.EmailTemplateContent{Subject: new(sesapi.EmailTemplateSubject(cfnComputeString(template, "SubjectPart")))}
	if template["TextPart"] != nil {
		content.Text = new(sesapi.EmailTemplateText(cfnComputeString(template, "TextPart")))
	}
	if template["HtmlPart"] != nil {
		content.Html = new(sesapi.EmailTemplateHtml(cfnComputeString(template, "HtmlPart")))
	}
	return content, nil
}
func cfnSESTemplateName(p map[string]any) string {
	template, _ := cfnComputeObject(p["Template"])
	return cfnComputeString(template, "TemplateName")
}
func (h cfnSESTemplate) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnSESTemplateName(a) != cfnSESTemplateName(b), nil
}
func (h cfnSESTemplate) get(ctx context.Context, name string) (*sesapi.GetEmailTemplateOutput, error) {
	return cfnTrustTyped[sesapi.GetEmailTemplateOutput](ctx, h.commands, "sesv2", "GetEmailTemplate", &sesapi.GetEmailTemplateInput{TemplateName: new(sesapi.EmailTemplateName(name))})
}
func cfnSESTemplateResult(name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Id": name}}
}
func (h cfnSESTemplate) update(ctx context.Context, name string, content *sesapi.EmailTemplateContent) error {
	_, err := cfnTrustTyped[sesapi.UpdateEmailTemplateOutput](ctx, h.commands, "sesv2", "UpdateEmailTemplate", &sesapi.UpdateEmailTemplateInput{TemplateName: new(sesapi.EmailTemplateName(name)), TemplateContent: content})
	return err
}
func (h cfnSESTemplate) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	content, _ := cfnSESTemplateContent(r.Properties)
	name := cfnSESTemplateName(r.Properties)
	if name == "" {
		generated := r
		generated.PhysicalID = ""
		generated.Properties = cloudformation.Properties{}
		name = cfnComputeName(generated, "TemplateName", 64)
	}
	claim := cfnTrustClaim(r, "sestemplate")
	rows := map[string]string{}
	_, err := h.get(sesv2.WithCloudFormationOwnership(ctx, "", false, rows), name)
	switch {
	case err == nil && rows[name] == claim:
		if err := h.update(sesv2.WithCloudFormationOwnership(ctx, claim, true, nil), name, content); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	case err == nil:
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("SES template %s is not owned by this stack resource incarnation", name))
	case cfnSESMissing(err):
		in := &sesapi.CreateEmailTemplateInput{TemplateName: new(sesapi.EmailTemplateName(name)), TemplateContent: content}
		if _, err := cfnTrustTyped[sesapi.CreateEmailTemplateOutput](sesv2.WithCloudFormationOwnership(ctx, claim, true, nil), h.commands, "sesv2", "CreateEmailTemplate", in); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	default:
		return cloudformation.ResourceResult{}, err
	}
	return cfnSESTemplateResult(name), nil
}

// ownership binds stack mutations to their incarnation; Cloud Control mutations
// keep the retained claim.
func (h cfnSESTemplate) ownership(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return sesv2.WithCloudFormationOwnership(ctx, cfnTrustClaim(r, "sestemplate"), true, nil)
}
func (h cfnSESTemplate) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::SES::Template", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	content, _ := cfnSESTemplateContent(r.Properties)
	if err := h.update(h.ownership(ctx, r), r.PhysicalID, content); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnSESTemplateResult(r.PhysicalID), nil
}
func (h cfnSESTemplate) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = h.ownership(ctx, r)
	if _, err := h.get(ctx, r.PhysicalID); err != nil {
		return cfnSESAbsent(r, err)
	}
	_, err := cfnTrustTyped[sesapi.DeleteEmailTemplateOutput](ctx, h.commands, "sesv2", "DeleteEmailTemplate", &sesapi.DeleteEmailTemplateInput{TemplateName: new(sesapi.EmailTemplateName(r.PhysicalID))})
	return cfnSESAbsent(r, err)
}
func cfnSESTemplateProperties(name string, t *sesapi.GetEmailTemplateOutput) cloudformation.Properties {
	template := map[string]any{"TemplateName": name}
	if t.TemplateContent != nil {
		template["SubjectPart"] = cfnComputeValue(t.TemplateContent.Subject)
		if text := cfnComputeValue(t.TemplateContent.Text); text != "" {
			template["TextPart"] = text
		}
		if html := cfnComputeValue(t.TemplateContent.Html); html != "" {
			template["HtmlPart"] = html
		}
	}
	return cloudformation.Properties{"Id": name, "Template": template}
}
func (h cfnSESTemplate) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	t, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return cfnSESTemplateProperties(r.PhysicalID, t), nil
}
func (h cfnSESTemplate) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	in := &sesapi.ListEmailTemplatesInput{}
	for {
		page, err := cfnTrustTyped[sesapi.ListEmailTemplatesOutput](ctx, h.commands, "sesv2", "ListEmailTemplates", in)
		if err != nil {
			return nil, err
		}
		for _, meta := range page.TemplatesMetadata {
			name := cfnComputeValue(meta.TemplateName)
			t, err := h.get(ctx, name)
			if err != nil {
				return nil, err
			}
			out = append(out, cloudformation.ResourceDescription{Identifier: name, Properties: cfnSESTemplateProperties(name, t)})
		}
		if page.NextToken == nil || cfnComputeValue(page.NextToken) == "" {
			return out, nil
		}
		in = &sesapi.ListEmailTemplatesInput{NextToken: page.NextToken}
	}
}
