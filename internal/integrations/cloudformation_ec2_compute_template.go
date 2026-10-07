package integrations

import (
	"context"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

type cfnEC2LaunchTemplate struct{ commands StepFunctionsCommands }

func (h cfnEC2LaunchTemplate) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "LaunchTemplateData", "LaunchTemplateName", "TagSpecifications", "VersionDescription"); err != nil {
		return err
	}
	data, ok := cfnComputeObject(p["LaunchTemplateData"])
	if !ok || len(data) == 0 {
		return fmt.Errorf("LaunchTemplateData must be a nonempty object")
	}
	if err := cfnComputeStrings(p, "LaunchTemplateName", "VersionDescription"); err != nil {
		return err
	}
	_, err := cfnEC2TemplateRequest(cloudformation.ResourceRequest{Properties: p})
	return err
}
func (h cfnEC2LaunchTemplate) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "LaunchTemplateName"), nil
}

func cfnEC2TemplateRequest(r cloudformation.ResourceRequest) (cloudformation.ResourceRequest, error) {
	p := cfnComputeCopy(r.Properties, "LaunchTemplateData", "LaunchTemplateName", "VersionDescription")
	var tags any
	if raw, found := r.Properties["TagSpecifications"]; found {
		list, ok := raw.([]any)
		if !ok {
			return r, fmt.Errorf("TagSpecifications must be a list")
		}
		if len(list) > 1 {
			return r, fmt.Errorf("only one launch-template tag specification is allowed")
		}
		for _, item := range list {
			spec, ok := cfnComputeObject(item)
			if !ok {
				return r, fmt.Errorf("TagSpecifications entries must be objects")
			}
			if err := cfnComputeProperties(spec, "ResourceType", "Tags"); err != nil {
				return r, err
			}
			if cfnComputeString(spec, "ResourceType") != "launch-template" {
				return r, fmt.Errorf("TagSpecifications ResourceType must be launch-template")
			}
			tags = spec["Tags"]
		}
	}
	if tags != nil {
		p["Tags"] = tags
	}
	if _, err := cfnEC2NetworkTags(p); err != nil {
		return r, err
	}
	r.Properties = p
	return r, nil
}
func (h cfnEC2LaunchTemplate) templates(ctx context.Context, in map[string]any) ([]api.LaunchTemplate, error) {
	rows := []api.LaunchTemplate{}
	for {
		out, err := cfnComputeCall[api.DescribeLaunchTemplatesResult](ctx, h.commands, "ec2", "DescribeLaunchTemplates", in)
		if err != nil {
			return nil, err
		}
		rows = append(rows, out.LaunchTemplates...)
		if cfnComputeValue(out.NextToken) == "" {
			return rows, nil
		}
		in["NextToken"] = *out.NextToken
	}
}
func (h cfnEC2LaunchTemplate) get(ctx context.Context, id string) (api.LaunchTemplate, error) {
	rows, err := h.templates(ctx, map[string]any{"LaunchTemplateIds": []string{id}})
	if err != nil {
		return api.LaunchTemplate{}, err
	}
	if len(rows) != 1 {
		return api.LaunchTemplate{}, cfnEC2ComputeMissing("launch template", id)
	}
	return rows[0], nil
}
func cfnEC2TemplateResult(v api.LaunchTemplate) cloudformation.ResourceResult {
	id := cfnComputeValue(v.LaunchTemplateId)
	attrs := map[string]any{"LaunchTemplateId": id}
	if v.DefaultVersionNumber != nil {
		attrs["DefaultVersionNumber"] = strconv.FormatInt(int64(*v.DefaultVersionNumber), 10)
	}
	if v.LatestVersionNumber != nil {
		attrs["LatestVersionNumber"] = strconv.FormatInt(int64(*v.LatestVersionNumber), 10)
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: attrs}
}
func (h cfnEC2LaunchTemplate) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id != "" {
		r.PhysicalID = id
		return h.RecoverCreation(ctx, r)
	}
	tr, err := cfnEC2TemplateRequest(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "LaunchTemplateData", "VersionDescription")
	in["LaunchTemplateName"] = cfnComputeName(r, "LaunchTemplateName", 128)
	in["ClientToken"] = cfnComputeHash(r.Token)
	in["TagSpecifications"] = cfnEC2NetworkTagSpecifications(tr, "launch-template")
	out, err := cfnComputeCall[api.CreateLaunchTemplateResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateLaunchTemplate", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if out.LaunchTemplate == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("CreateLaunchTemplate returned no template")
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(out.LaunchTemplate.LaunchTemplateId)); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEC2TemplateResult(*out.LaunchTemplate), nil
}
func (h cfnEC2LaunchTemplate) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.LaunchTemplateId)); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnEC2NativeContext(ctx, r, "mutate")
	if cfnComputeChanged(r.Previous, r.Properties, "LaunchTemplateData", "VersionDescription") {
		current, err := h.projection(ctx, v)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if !cfnEC2ComputeEqual(current["LaunchTemplateData"], r.Properties["LaunchTemplateData"]) || cfnComputeString(current, "VersionDescription") != cfnComputeString(r.Properties, "VersionDescription") {
			in := cfnComputeCopy(r.Properties, "LaunchTemplateData", "VersionDescription")
			in["LaunchTemplateId"] = r.PhysicalID
			body, _ := cfnComputeDocument(in)
			// The current version disambiguates A -> B -> A updates. First
			// observe the desired latest version so a lost reply cannot append
			// another version on replay.
			if v.LatestVersionNumber == nil {
				return cloudformation.ResourceResult{}, fmt.Errorf("DescribeLaunchTemplates returned no latest version number")
			}
			in["ClientToken"] = cfnComputeHash(r.Token + "/" + strconv.FormatInt(int64(*v.LatestVersionNumber), 10) + "/" + body)
			if _, err := cfnComputeCall[api.CreateLaunchTemplateVersionResult](ctx, h.commands, "ec2", "CreateLaunchTemplateVersion", in); err != nil {
				return cloudformation.ResourceResult{}, err
			}
		}
	}
	tr, err := cfnEC2TemplateRequest(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	previous, err := cfnEC2TemplateRequest(cloudformation.ResourceRequest{Properties: r.Previous})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tr.Previous = previous.Properties
	if err := cfnEC2NetworkUpdateTags(ctx, h.commands, tr, r.PhysicalID, cfnEC2Tags(v.Tags)); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	v, err = h.get(ctx, r.PhysicalID)
	return cfnEC2TemplateResult(v), err
}
func (h cfnEC2LaunchTemplate) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.get(ctx, r.PhysicalID)
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.LaunchTemplateId)); err != nil {
		return err
	}
	err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteLaunchTemplate", map[string]any{"LaunchTemplateId": r.PhysicalID})
	if cfnEC2Missing(err) {
		return nil
	}
	return err
}
func (h cfnEC2LaunchTemplate) projection(ctx context.Context, v api.LaunchTemplate) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.DescribeLaunchTemplateVersionsResult](ctx, h.commands, "ec2", "DescribeLaunchTemplateVersions", map[string]any{"LaunchTemplateId": cfnComputeValue(v.LaunchTemplateId), "Versions": []string{"$Latest"}})
	if err != nil {
		return nil, err
	}
	if len(out.LaunchTemplateVersions) != 1 {
		return nil, fmt.Errorf("launch template has no latest version")
	}
	version := out.LaunchTemplateVersions[0]
	data, err := cfnEC2ComputeProjection(version.LaunchTemplateData)
	if err != nil {
		return nil, err
	}
	if metadata, ok := cfnComputeObject(data["MetadataOptions"]); ok {
		delete(metadata, "State")
	}
	p := cloudformation.Properties{"LaunchTemplateId": cfnComputeValue(v.LaunchTemplateId), "LaunchTemplateName": cfnComputeValue(v.LaunchTemplateName), "LaunchTemplateData": data, "VersionDescription": cfnComputeValue(version.VersionDescription), "TagSpecifications": []any{map[string]any{"ResourceType": "launch-template", "Tags": cfnEC2ComputePublicTags(v.Tags)}}}
	for k, val := range cfnEC2TemplateResult(v).Attributes {
		p[k] = val
	}
	return p, nil
}
func (h cfnEC2LaunchTemplate) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.LaunchTemplateId)); err != nil {
		return nil, err
	}
	return h.projection(ctx, v)
}
func (h cfnEC2LaunchTemplate) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows, err := h.templates(ctx, map[string]any{})
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, v := range rows {
		if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.LaunchTemplateId)); err != nil {
			continue
		}
		p, err := h.projection(ctx, v)
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.LaunchTemplateId), Properties: p})
	}
	return out, nil
}
func (h cfnEC2LaunchTemplate) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.LaunchTemplateId)); err != nil {
		return false, err
	}
	p, err := h.projection(ctx, v)
	if err != nil {
		return false, err
	}
	return cfnEC2ComputeEqual(p["LaunchTemplateData"], r.Properties["LaunchTemplateData"]) && cfnComputeString(p, "VersionDescription") == cfnComputeString(r.Properties, "VersionDescription"), nil
}
func (h cfnEC2LaunchTemplate) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.get(ctx, r.PhysicalID)
	if cfnEC2Missing(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.LaunchTemplateId))
}
func (h cfnEC2LaunchTemplate) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id == "" {
		return cloudformation.ResourceResult{}, cfnEC2NotFound(r.Type)
	}
	v, err := h.get(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEC2TemplateResult(v), cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.LaunchTemplateId))
}
