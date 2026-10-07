package integrations

import (
	"context"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-trigger.html
type cfnGlueTrigger struct{ commands StepFunctionsCommands }

func (h cfnGlueTrigger) Validate(p cloudformation.Properties) error {
	if err := cfnGlueTriggerAdmission(p); err != nil {
		return err
	}
	if err := cfnComputeProperties(p, "Type", "StartOnCreation", "Description", "Actions", "EventBatchingCondition", "WorkflowName", "Schedule", "Tags", "Name", "Predicate"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Trigger", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueTrigger) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "WorkflowName", "Type"), h.Validate(b)
}
func (h cfnGlueTrigger) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnGlueClaim(ctx, r, "trigger", name)
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
	input := cfnComputeCopy(r.Properties, "Type", "StartOnCreation", "Description", "Actions", "EventBatchingCondition", "WorkflowName", "Schedule", "Name", "Predicate")
	input["Name"] = name
	input["Tags"] = cfnAnalyticsCustomerTags(r)
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateTrigger", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(name, name, nil), nil
}
func (h cfnGlueTrigger) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := r.PhysicalID
	ctx = cfnGlueClaim(ctx, r, "trigger", name)
	input := map[string]any{"Name": name, "TriggerUpdate": cfnComputeCopy(r.Properties, "Description", "Actions", "EventBatchingCondition", "Schedule", "Predicate")}
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateTrigger", input); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	if err := cfnGlueTriggerActivation(ctx, h.commands, r); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	return cfnAnalyticsResult(name, name, nil), cfnGlueUpdateTags(ctx, h.commands, r, cfnGlueARN(r, "trigger", name))
}
func (h cfnGlueTrigger) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 255)
	r.PhysicalID = name
	ctx = cfnGlueClaim(ctx, r, "trigger", name)
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteTrigger", map[string]any{"Name": name}))
}
func (h cfnGlueTrigger) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := r.PhysicalID
	ctx = cfnGlueClaim(ctx, r, "trigger", name)
	out, err := cfnComputeCall[api.GetTriggerOutput](ctx, h.commands, "glue", "GetTrigger", map[string]any{"Name": name})
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	p, err := cfnAnalyticsProject(out.Trigger, "Type", "StartOnCreation", "Description", "Actions", "EventBatchingCondition", "WorkflowName", "Schedule", "Name", "Predicate")
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	tags, err := cfnGlueTags(ctx, h.commands, cfnGlueARN(r, "trigger", name))
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	p["Tags"] = tags
	if out.Trigger != nil && cfnComputeValue(out.Trigger.Type) != "ON_DEMAND" {
		p["StartOnCreation"] = cfnComputeValue(out.Trigger.State) == "ACTIVATED"
	}
	return p, nil
}
func (h cfnGlueTrigger) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.GetTriggersOutput](ctx, h.commands, "glue", "GetTriggers", input)
		if err != nil {
			return nil, cfnAnalyticsReadError(err)
		}
		for _, v := range out.Triggers {
			r.PhysicalID = cfnComputeValue(v.Name)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, cfnAnalyticsReadError(err)
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
