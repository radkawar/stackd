package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-registry.html
type cfnGlueRegistry struct{ commands StepFunctionsCommands }

func (h cfnGlueRegistry) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Tags"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Registry", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueRegistry) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnGlueRegistry) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := r.PhysicalID
	if id == "" {
		id = cfnGlueARN(r, "registry", cfnComputeName(r, "Name", 255))
	}
	name := strings.TrimPrefix(id, cfnGlueARN(r, "registry", ""))
	r.PhysicalID = id
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	_, err := h.Read(ctx, r)
	if err == nil {
		return h.Result(ctx, r)
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := map[string]any{"RegistryName": name, "Description": cfnComputeDefault(r.Properties, "Description", ""), "Tags": cfnAnalyticsCustomerTags(r)}
	out, err := cfnComputeCall[api.CreateRegistryOutput](ctx, h.commands, "glue", "CreateRegistry", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeValue(out.RegistryArn)
	return h.Result(ctx, r)
}
func (h cfnGlueRegistry) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	input := map[string]any{"RegistryId": map[string]any{"RegistryArn": id}}
	input["Description"] = cfnComputeDefault(r.Properties, "Description", "")
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateRegistry", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnGlueUpdateTags(ctx, h.commands, r, id); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.Result(ctx, r)
}
func (h cfnGlueRegistry) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteRegistry", map[string]any{"RegistryId": map[string]any{"RegistryArn": id}}))
}
func (h cfnGlueRegistry) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	out, err := cfnComputeCall[api.GetRegistryOutput](ctx, h.commands, "glue", "GetRegistry", map[string]any{"RegistryId": map[string]any{"RegistryArn": id}})
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"Arn": id, "Name": cfnComputeValue(out.RegistryName)}
	if out.Description != nil {
		p["Description"] = string(*out.Description)
	}
	tags, err := cfnGlueTags(ctx, h.commands, id)
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnComputeTagList(tags)
	return p, nil
}
func (h cfnGlueRegistry) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListRegistriesOutput](ctx, h.commands, "glue", "ListRegistries", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Registries {
			if cfnComputeValue(v.Status) == "DELETING" {
				continue
			}
			r.PhysicalID = cfnComputeValue(v.RegistryArn)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		input["NextToken"] = out.NextToken
	}
	return cfnAnalyticsSort(rows), nil
}
func (h cfnGlueRegistry) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	result := cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, map[string]any{"Arn": r.PhysicalID})
	_, err := h.Read(ctx, r)
	return result, err
}
func (h cfnGlueRegistry) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	out, err := cfnComputeCall[api.GetRegistryOutput](ctx, h.commands, "glue", "GetRegistry", map[string]any{"RegistryId": map[string]any{"RegistryArn": r.PhysicalID}})
	if err != nil {
		return false, err
	}
	status := cfnComputeValue(out.Status)
	if status == "AVAILABLE" {
		return true, nil
	}
	if status == "PENDING" {
		return false, nil
	}
	return false, fmt.Errorf("glue registry is %s", status)
}
func (h cfnGlueRegistry) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	_, err := cfnComputeCall[api.GetRegistryOutput](ctx, h.commands, "glue", "GetRegistry", map[string]any{"RegistryId": map[string]any{"RegistryArn": r.PhysicalID}})
	if cfnAnalyticsGone(err) {
		return true, nil
	}
	return false, err
}
