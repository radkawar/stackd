package integrations

import (
	"context"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-workflow.html
type cfnGlueWorkflow struct{ commands StepFunctionsCommands }

func (h cfnGlueWorkflow) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Description", "Tags", "DefaultRunProperties", "Name", "MaxConcurrentRuns"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Workflow", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueWorkflow) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnGlueWorkflow) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnGlueClaim(ctx, r, "workflow", name)
	_, err := h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(name, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "DefaultRunProperties", "Name", "MaxConcurrentRuns")
	input["Name"] = name
	input["Tags"] = cfnAnalyticsCustomerTags(r)
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateWorkflow", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(name, name, nil), nil
}
func (h cfnGlueWorkflow) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := r.PhysicalID
	ctx = cfnGlueClaim(ctx, r, "workflow", name)
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateWorkflow", cfnGlueWorkflowUpdateInput(r)); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	return cfnAnalyticsResult(name, name, nil), cfnGlueUpdateTags(ctx, h.commands, r, cfnGlueARN(r, "workflow", name))
}
func (h cfnGlueWorkflow) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnGlueClaim(ctx, r, "workflow", name)
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteWorkflow", map[string]any{"Name": name}))
}
func (h cfnGlueWorkflow) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := r.PhysicalID
	ctx = cfnGlueClaim(ctx, r, "workflow", name)
	out, err := cfnComputeCall[api.GetWorkflowOutput](ctx, h.commands, "glue", "GetWorkflow", map[string]any{"Name": name})
	if err != nil {
		return nil, err
	}
	p, err := cfnAnalyticsProject(out.Workflow, "Description", "DefaultRunProperties", "Name", "MaxConcurrentRuns")
	if err != nil {
		return nil, err
	}
	tags, err := cfnGlueTags(ctx, h.commands, cfnGlueARN(r, "workflow", name))
	if err != nil {
		return nil, err
	}
	p["Tags"] = tags
	return p, nil
}
func (h cfnGlueWorkflow) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListWorkflowsOutput](ctx, h.commands, "glue", "ListWorkflows", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Workflows {
			r.PhysicalID = string(v)
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
