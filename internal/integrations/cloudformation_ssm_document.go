package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// cfnSSMDocument provisions customer SSM documents through the SSM document
// owner, which retains document types, content validation, versions, sharing
// and tags. The owner stores this incarnation's private claim on the document
// row; tags are public metadata and never prove ownership.
type cfnSSMDocument struct{ commands StepFunctionsCommands }
type cfnSSMDocumentProperties struct {
	Attachments    []any
	Content        any
	DocumentFormat string
	DocumentType   string
	Name           string
	Requires       []struct{ Name, Version string }
	Tags           []cfnMessagingTag
	TargetType     string
	UpdateMethod   string
	VersionName    string
}

var cfnSSMDocumentName = regexp.MustCompile(`^[a-zA-Z0-9_\-.]{3,128}$`)
var cfnSSMDocumentVersionName = regexp.MustCompile(`^[a-zA-Z0-9_\-.]{1,128}$`)
var cfnSSMDocumentTargetType = regexp.MustCompile(`^\/[\w\.\-\:\/]*$`)

func (h cfnSSMDocument) decode(raw cloudformation.Properties) (cfnSSMDocumentProperties, error) {
	var p cfnSSMDocumentProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	if p.Name != "" && !cfnSSMDocumentName.MatchString(p.Name) {
		return p, fmt.Errorf("name must match %s", cfnSSMDocumentName)
	}
	if p.VersionName != "" && !cfnSSMDocumentVersionName.MatchString(p.VersionName) {
		return p, fmt.Errorf("VersionName must match %s", cfnSSMDocumentVersionName)
	}
	if p.TargetType != "" && !cfnSSMDocumentTargetType.MatchString(p.TargetType) {
		return p, fmt.Errorf("TargetType must match %s", cfnSSMDocumentTargetType)
	}
	switch p.DocumentFormat {
	case "", "JSON", "YAML", "TEXT":
	default:
		return p, fmt.Errorf("DocumentFormat must be YAML, JSON or TEXT")
	}
	switch p.UpdateMethod {
	case "", "Replace", "NewVersion":
	default:
		return p, fmt.Errorf("UpdateMethod must be Replace or NewVersion")
	}
	// TODO: Comeback attachments need the document owner's attachment storage.
	if len(p.Attachments) != 0 {
		return p, fmt.Errorf("SSM document Attachments are not implemented by the SSM document owner")
	}
	if _, err := p.content(); err != nil {
		return p, err
	}
	_, err := cfnComputeTags(raw)
	return p, err
}
func (p cfnSSMDocumentProperties) format() string {
	if p.DocumentFormat == "" {
		return "JSON"
	}
	return p.DocumentFormat
}

// content serializes object content in the declared format. String content is
// passed to the owner verbatim.
func (p cfnSSMDocumentProperties) content() (string, error) {
	switch value := p.Content.(type) {
	case string:
		if value == "" {
			return "", fmt.Errorf("content must not be empty")
		}
		return value, nil
	case map[string]any:
		var raw []byte
		var err error
		switch p.format() {
		case "YAML":
			raw, err = yaml.Marshal(value)
		case "JSON":
			raw, err = json.Marshal(value)
		default:
			return "", fmt.Errorf("object Content requires DocumentFormat JSON or YAML")
		}
		return string(raw), err
	default:
		return "", fmt.Errorf("content is required and must be a JSON object or string")
	}
}
func (h cfnSSMDocument) Validate(raw cloudformation.Properties) error {
	_, err := h.decode(raw)
	return err
}
func (h cfnSSMDocument) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	named, _ := a["Name"].(string)
	return cfnMessagingReplacement(named != "" && named == b["Name"], cfnMessagingChanged(a, b, "Name", "DocumentType"))
}
func (h cfnSSMDocument) name(r cloudformation.ResourceRequest, p cfnSSMDocumentProperties) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	if p.Name != "" {
		return p.Name
	}
	return cfnComputeName(r, "Name", 128)
}
func (h cfnSSMDocument) tags(ctx context.Context, name string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, h.commands, "ssm", "ListTagsForResource", map[string]any{"ResourceType": "Document", "ResourceId": name})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, tag := range out.TagList {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}
func (h cfnSSMDocument) createInput(name string, p cfnSSMDocumentProperties, tags map[string]string) (map[string]any, error) {
	content, err := p.content()
	if err != nil {
		return nil, err
	}
	in := map[string]any{"Name": name, "Content": content, "DocumentFormat": p.format(), "Tags": cfnComputeTagList(tags)}
	if p.DocumentType != "" {
		in["DocumentType"] = p.DocumentType
	}
	if p.TargetType != "" {
		in["TargetType"] = p.TargetType
	}
	if p.VersionName != "" {
		in["VersionName"] = p.VersionName
	}
	if len(p.Requires) != 0 {
		requires := make([]map[string]string, 0, len(p.Requires))
		for _, required := range p.Requires {
			item := map[string]string{"Name": required.Name}
			if required.Version != "" {
				item["Version"] = required.Version
			}
			requires = append(requires, item)
		}
		in["Requires"] = requires
	}
	return in, nil
}
func (h cfnSSMDocument) create(ctx context.Context, name string, p cfnSSMDocumentProperties, tags map[string]string) error {
	in, err := h.createInput(name, p, tags)
	if err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "ssm", "CreateDocument", in)
}
func (h cfnSSMDocument) replace(ctx context.Context, name string, p cfnSSMDocumentProperties, desired map[string]string) error {
	provider, ok := h.commands.providers["ssm"]
	if !ok {
		return fmt.Errorf("SSM document owner unavailable")
	}
	owner, ok := provider.executor.(interface {
		CloudFormationReplaceDocument(context.Context, *api.CreateDocumentRequest) (*api.CreateDocumentResult, *awswire.Error)
	})
	if !ok {
		return fmt.Errorf("SSM document owner has no atomic replacement admission")
	}
	input, err := h.createInput(name, p, desired)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	op, ok := provider.model.Operation("CreateDocument")
	if !ok {
		return fmt.Errorf("SSM CreateDocument model unavailable")
	}
	in := &api.CreateDocumentRequest{}
	if err := awsapi.DecodeCloudFormationInput(provider.model, op, raw, in); err != nil {
		return err
	}
	_, rejected := owner.CloudFormationReplaceDocument(ctx, in)
	if rejected != nil {
		return rejected
	}
	return nil
}
func (h cfnSSMDocument) describe(ctx context.Context, name string) (*api.DocumentDescription, error) {
	out, err := cfnComputeCall[api.DescribeDocumentResult](ctx, h.commands, "ssm", "DescribeDocument", map[string]any{"Name": name})
	if err != nil {
		return nil, cfnStorageMissing(err, "InvalidDocument")
	}
	if out.Document == nil {
		return nil, fmt.Errorf("SSM returned no document")
	}
	return out.Document, nil
}
func (h cfnSSMDocument) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.decode(r.Properties)
	if err != nil {
		if admitted, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	name := h.name(r, p)
	ctx = cfnSSMDocumentContext(ctx, r, true)
	// The owner admits a new document with this claim, or returns the document
	// this exact incarnation already committed; any other is rejected.
	// Stack marker tags are descriptive metadata only; the private claim fences.
	if err := h.create(ctx, name, p, cfnResourceTags(r)); err != nil {
		if cfnMessagingMissing(err, "DocumentAlreadyExists") {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, err)
		}
		admitted, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, errors.Join(err, recoveryErr)
	}
	return cfnMessagingResult(name), nil
}

// RecoverCreation identifies only the admitted document carrying this exact
// incarnation's private claim. Names, tags or matching content never prove
// admission.
func (h cfnSSMDocument) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p := cfnSSMDocumentProperties{Name: cfnComputeString(r.Properties, "Name")}
	name := h.name(r, p)
	if _, err := h.describe(cfnSSMDocumentContext(ctx, r, true), name); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnMessagingResult(name), nil
}
func (h cfnSSMDocument) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::SSM::Document", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	ctx = cfnSSMDocumentContext(ctx, r, false)
	result := cfnMessagingResult(r.PhysicalID)
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replace {
		return result, fmt.Errorf("document update requires replacement")
	}
	old, err := h.decode(r.Previous)
	if err != nil {
		return result, err
	}
	next, err := h.decode(r.Properties)
	if err != nil {
		return result, err
	}
	tags, err := h.tags(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	desired := cfnResourceTags(r)
	oldContent, _ := old.content()
	nextContent, err := next.content()
	if err != nil {
		return result, err
	}
	documentChanged := oldContent != nextContent || old.format() != next.format() || old.VersionName != next.VersionName || old.TargetType != next.TargetType || !reflect.DeepEqual(old.Requires, next.Requires)
	if documentChanged {
		if next.UpdateMethod == "NewVersion" {
			if !reflect.DeepEqual(old.Requires, next.Requires) {
				return result, fmt.Errorf("requires cannot change in a new document version; use UpdateMethod Replace")
			}
			if err := h.newVersion(ctx, r.PhysicalID, next, nextContent); err != nil {
				return result, err
			}
		} else {
			// Admission, retirement and native audit share one owner transaction.
			// A rejected replacement leaves all old versions and shares untouched.
			if err := h.replace(ctx, r.PhysicalID, next, desired); err != nil {
				return result, err
			}
			return result, nil
		}
	}
	if removed := cfnComputeRemovedTags(tags, desired); len(removed) != 0 {
		if err := cfnComputeRun(ctx, h.commands, "ssm", "RemoveTagsFromResource", map[string]any{"ResourceType": "Document", "ResourceId": r.PhysicalID, "TagKeys": removed}); err != nil {
			return result, err
		}
	}
	if len(desired) != 0 {
		if err := cfnComputeRun(ctx, h.commands, "ssm", "AddTagsToResource", map[string]any{"ResourceType": "Document", "ResourceId": r.PhysicalID, "Tags": cfnComputeTagList(desired)}); err != nil {
			return result, err
		}
	}
	return result, nil
}
func (h cfnSSMDocument) newVersion(ctx context.Context, name string, p cfnSSMDocumentProperties, content string) error {
	in := map[string]any{"Name": name, "Content": content, "DocumentFormat": p.format(), "DocumentVersion": "$LATEST"}
	if p.TargetType != "" {
		in["TargetType"] = p.TargetType
	}
	if p.VersionName != "" {
		in["VersionName"] = p.VersionName
	}
	out, err := cfnComputeCall[api.UpdateDocumentResult](ctx, h.commands, "ssm", "UpdateDocument", in)
	if err != nil {
		return err
	}
	if out.DocumentDescription == nil || out.DocumentDescription.DocumentVersion == nil {
		return fmt.Errorf("SSM returned no document version")
	}
	return cfnComputeRun(ctx, h.commands, "ssm", "UpdateDocumentDefaultVersion", map[string]any{"Name": name, "DocumentVersion": string(*out.DocumentDescription.DocumentVersion)})
}
func (h cfnSSMDocument) delete(ctx context.Context, name string) error {
	document, err := h.describe(ctx, name)
	if err != nil {
		return err
	}
	in := map[string]any{"Name": name}
	if cfnComputeValue(document.DocumentType) == "ApplicationConfigurationSchema" {
		in["Force"] = true
	}
	return cfnComputeRun(ctx, h.commands, "ssm", "DeleteDocument", in)
}
func (h cfnSSMDocument) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		p, err := h.decode(r.Properties)
		if err != nil {
			return err
		}
		r.PhysicalID = h.name(r, p)
	}
	// Under a stack claim the owner observes and deletes only the document
	// this incarnation created; a same-name recreation is rejected.
	err := h.delete(cfnSSMDocumentContext(ctx, r, false), r.PhysicalID)
	if cfnMessagingMissing(err, "NotFound") && !r.CloudControl {
		return nil
	}
	return err
}
func (h cfnSSMDocument) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	document, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	return h.project(ctx, document)
}
func (h cfnSSMDocument) project(ctx context.Context, document *api.DocumentDescription) (cloudformation.Properties, error) {
	name := cfnComputeValue(document.Name)
	out, err := cfnComputeCall[api.GetDocumentResult](ctx, h.commands, "ssm", "GetDocument", map[string]any{"Name": name})
	if err != nil {
		return nil, cfnStorageMissing(err, "InvalidDocument")
	}
	format := cfnComputeValue(out.DocumentFormat)
	p := cloudformation.Properties{"Name": name, "DocumentType": cfnComputeValue(out.DocumentType), "DocumentFormat": format}
	content := cfnComputeValue(out.Content)
	if format == "JSON" {
		var object map[string]any
		if err := cfnStorageJSON(content, &object); err != nil {
			return nil, err
		}
		p["Content"] = object
	} else {
		p["Content"] = content
	}
	if out.VersionName != nil {
		p["VersionName"] = string(*out.VersionName)
	}
	if document.TargetType != nil {
		p["TargetType"] = string(*document.TargetType)
	}
	if len(out.Requires) != 0 {
		requires := make([]any, 0, len(out.Requires))
		for _, required := range out.Requires {
			item := map[string]any{"Name": cfnComputeValue(required.Name)}
			if required.Version != nil {
				item["Version"] = string(*required.Version)
			}
			requires = append(requires, item)
		}
		p["Requires"] = requires
	}
	tags, err := h.tags(ctx, name)
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnSSMDocument) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var resources []cloudformation.ResourceDescription
	in := map[string]any{"Filters": []map[string]any{{"Key": "Owner", "Values": []string{"Self"}}}, "MaxResults": 50}
	for {
		out, err := cfnComputeCall[api.ListDocumentsResult](ctx, h.commands, "ssm", "ListDocuments", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.DocumentIdentifiers {
			name := cfnComputeValue(row.Name)
			if strings.HasPrefix(name, "arn:") {
				continue // Shared documents are owned by another account.
			}
			document, err := h.describe(ctx, name)
			if err != nil {
				return nil, err
			}
			p, err := h.project(ctx, document)
			if err != nil {
				return nil, err
			}
			resources = append(resources, cloudformation.ResourceDescription{Identifier: name, Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return resources, nil
		}
		in["NextToken"] = string(*out.NextToken)
	}
}

var _ cloudformation.ResourceReader = cfnSSMDocument{}
