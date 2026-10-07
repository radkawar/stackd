package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-athena-workgroup.html
type cfnAthenaWorkGroup struct{ commands StepFunctionsCommands }

func (h cfnAthenaWorkGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Tags", "WorkGroupConfiguration", "WorkGroupConfigurationUpdates", "State", "RecursiveDeleteOption"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Athena::WorkGroup", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnAthenaWorkGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnAthenaWorkGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 128)
	if name == "primary" {
		return cloudformation.ResourceResult{}, fmt.Errorf("the primary workgroup is service-managed")
	}
	r.PhysicalID = name
	ctx = cfnAthenaWorkGroupClaim(ctx, r, name)
	_, err := h.Read(ctx, r)
	if err != nil {
		if !cfnAnalyticsMissing(err) {
			return cloudformation.ResourceResult{}, err
		}
		if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		input := cfnComputeCopy(r.Properties, "Description")
		input["Name"] = name
		input["Configuration"] = r.Properties["WorkGroupConfiguration"]
		input["Tags"] = cfnComputeTagList(cfnAnalyticsCustomerTags(r))
		if err = cfnComputeRun(ctx, h.commands, "athena", "CreateWorkGroup", input); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	input := map[string]any{"WorkGroup": name, "State": cfnComputeDefault(r.Properties, "State", "ENABLED")}
	if r.Properties["WorkGroupConfigurationUpdates"] != nil {
		input["ConfigurationUpdates"] = cfnAthenaConfigurationUpdates(r)
	}
	if err = cfnComputeRun(ctx, h.commands, "athena", "UpdateWorkGroup", input); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	return h.Result(ctx, r)
}
func (h cfnAthenaWorkGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.Create(cfnAnalyticsRecovery(ctx), r)
}
func (h cfnAthenaWorkGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := r.PhysicalID
	ctx = cfnAthenaWorkGroupClaim(ctx, r, name)
	input := map[string]any{"WorkGroup": name, "Description": cfnComputeDefault(r.Properties, "Description", ""), "State": cfnComputeDefault(r.Properties, "State", "ENABLED"), "ConfigurationUpdates": cfnAthenaConfigurationUpdates(r)}
	if err := cfnComputeRun(ctx, h.commands, "athena", "UpdateWorkGroup", input); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	if err := cfnAthenaUpdateTags(ctx, h.commands, r, cfnAthenaARN(r, "workgroup", name)); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	return h.Result(ctx, r)
}
func (h cfnAthenaWorkGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 128)
	ctx = cfnAthenaWorkGroupClaim(ctx, r, name)
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "athena", "DeleteWorkGroup", map[string]any{"WorkGroup": name, "RecursiveDeleteOption": cfnComputeDefault(r.Properties, "RecursiveDeleteOption", false)}))
}
func (h cfnAthenaWorkGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := r.PhysicalID
	ctx = cfnAthenaWorkGroupClaim(ctx, r, name)
	out, err := cfnComputeCall[api.GetWorkGroupOutput](ctx, h.commands, "athena", "GetWorkGroup", map[string]any{"WorkGroup": name})
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	p, err := cfnAnalyticsProject(out.WorkGroup, "Name", "Description", "State", "CreationTime")
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	if out.WorkGroup != nil {
		configuration, err := cfnAnalyticsMap(out.WorkGroup.Configuration)
		if err != nil {
			return nil, cfnAnalyticsReadError(err)
		}
		p["WorkGroupConfiguration"] = map[string]any(configuration)
		if out.WorkGroup.CreationTime != nil {
			p["CreationTime"] = cfnAthenaEpoch(out.WorkGroup.CreationTime)
		}
	}
	tags, err := cfnAthenaTags(ctx, h.commands, cfnAthenaARN(r, "workgroup", name))
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	p["Tags"] = cfnComputeTagList(tags)
	return p, nil
}
func (h cfnAthenaWorkGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListWorkGroupsOutput](ctx, h.commands, "athena", "ListWorkGroups", input)
		if err != nil {
			return nil, cfnAnalyticsReadError(err)
		}
		for _, v := range out.WorkGroups {
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
