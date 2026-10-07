package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/codebuild"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-fleet.html
var cfnCodeBuildFleetProperties = []string{"Name", "BaseCapacity", "EnvironmentType", "ComputeType", "OverflowBehavior", "FleetServiceRole", "FleetVpcConfig", "FleetProxyConfiguration", "Tags", "ImageId", "ScalingConfiguration", "ComputeConfiguration"}

type cfnCodeBuildFleet struct{ commands StepFunctionsCommands }

func (h cfnCodeBuildFleet) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnCodeBuildFleetProperties...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "BaseCapacity", "EnvironmentType", "ComputeType"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCodeBuildFleet) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnCodeBuildFleet) get(ctx context.Context, id string) (*api.Fleet, error) {
	out, err := cfnComputeCall[api.BatchGetFleetsOutput](ctx, h.commands, "codebuild", "BatchGetFleets", map[string]any{"names": []string{id}})
	if err != nil {
		return nil, err
	}
	if len(out.Fleets) != 1 {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Fleet not found", StatusCode: 400}
	}
	return &out.Fleets[0], nil
}
func cfnCodeBuildFleetInput(p cloudformation.Properties) map[string]any {
	in := cfnDeveloperInput(p, cfnCodeBuildFleetProperties...)
	if v, ok := in["fleetVpcConfig"]; ok {
		in["vpcConfig"] = v
		delete(in, "fleetVpcConfig")
	}
	if v, ok := in["fleetProxyConfiguration"]; ok {
		in["proxyConfiguration"] = v
		delete(in, "fleetProxyConfiguration")
	}
	return in
}
func cfnCodeBuildFleetResult(p *api.Fleet) cloudformation.ResourceResult {
	id := cfnComputeValue(p.Arn)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": id}}
}
func (h cfnCodeBuildFleet) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id := cfnComputeName(r, "Name", 128)
	rows := map[string]string{}
	ctx = codebuild.WithCloudFormationResourceOwnership(ctx, "Fleet", cfnDeveloperClaim(r), "", true, rows)
	p, err := h.get(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if rows[cfnComputeValue(p.Arn)] != cfnDeveloperClaim(r) {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("fleet belongs to another CloudFormation incarnation"))
	}
	return cfnCodeBuildFleetResult(p), nil
}
func (h cfnCodeBuildFleet) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.RecoverCreation(ctx, r)
	if err == nil {
		return result, nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	ctx = codebuild.WithCloudFormationResourceOwnership(ctx, "Fleet", cfnDeveloperClaim(r), "", false, nil)
	in := cfnCodeBuildFleetInput(r.Properties)
	in["name"] = cfnComputeName(r, "Name", 128)
	in["tags"] = cfnECRTags(cfnResourceTags(r))
	out, err := cfnComputeCall[api.CreateFleetOutput](ctx, h.commands, "codebuild", "CreateFleet", in)
	if err != nil {
		recovered, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return recovered, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return cfnCodeBuildFleetResult(out.Fleet), nil
}
func (h cfnCodeBuildFleet) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDeveloperCodeBuildContext(ctx, r, "Fleet")
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnCodeBuildFleetInput(r.Properties)
	delete(in, "name")
	in["arn"] = r.PhysicalID
	in["overflowBehavior"] = cfnComputeDefault(r.Properties, "OverflowBehavior", "QUEUE")
	in["tags"] = cfnECRTags(cfnResourceTags(r))
	out, err := cfnComputeCall[api.UpdateFleetOutput](ctx, h.commands, "codebuild", "UpdateFleet", in)
	if err != nil {
		return cfnCodeBuildFleetResult(p), err
	}
	return cfnCodeBuildFleetResult(out.Fleet), nil
}
func (h cfnCodeBuildFleet) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnDeveloperCodeBuildContext(ctx, r, "Fleet")
	_, err := h.get(ctx, r.PhysicalID)
	if cfnComputeMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "codebuild", "DeleteFleet", map[string]any{"arn": r.PhysicalID})
}
func (h cfnCodeBuildFleet) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := cfnDeveloperModel(p, cfnCodeBuildFleetProperties...)
	if err != nil {
		return nil, err
	}
	out["Tags"] = cfnComputeTagList(cfnCodeBuildTags(p.Tags))
	out["Arn"] = cfnComputeValue(p.Arn)
	return out, nil
}
func (h cfnCodeBuildFleet) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	token := ""
	for {
		out, err := cfnComputeCall[api.ListFleetsOutput](ctx, h.commands, "codebuild", "ListFleets", cfnDeveloperPageInput(token, map[string]any{}))
		if err != nil {
			return nil, err
		}
		for _, id := range out.Fleets {
			r.PhysicalID = string(id)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		next := cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
		if next == token {
			return nil, fmt.Errorf("CodeBuild pagination did not advance")
		}
		token = next
	}
}
func (h cfnCodeBuildFleet) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if p.Status == nil {
		return false, fmt.Errorf("fleet has no status")
	}
	switch cfnComputeValue(p.Status.StatusCode) {
	case "ACTIVE":
		return true, nil
	case "CREATING", "UPDATING":
		return false, nil
	default:
		return false, fmt.Errorf("fleet failed: %s", cfnComputeValue(p.Status.StatusCode))
	}
}
func (h cfnCodeBuildFleet) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.get(ctx, r.PhysicalID)
	if cfnComputeMissing(err) {
		return true, nil
	}
	return false, err
}
