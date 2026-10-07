package integrations

import (
	"context"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/cloudformation"
)

// Qualified resources pin service-owned immutable revisions; they never copy
// state machine definitions into a CloudFormation resource database.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-stepfunctions-statemachineversion.html
type cfnStateMachineVersion struct{ commands StepFunctionsCommands }

func (h cfnStateMachineVersion) Validate(p cloudformation.Properties) error {
	return cfnWorkflowValidate(p, []string{"StateMachineArn"}, "StateMachineArn", "StateMachineRevisionId", "Description")
}
func (h cfnStateMachineVersion) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "StateMachineArn", "StateMachineRevisionId", "Description"), h.Validate(b)
}
func (h cfnStateMachineVersion) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in := cfnComputeCopy(r.Properties, "StateMachineArn", "Description")
	if revision := r.Properties["StateMachineRevisionId"]; revision != nil {
		in["RevisionId"] = revision
	}
	out, err := cfnComputeCall[api.PublishStateMachineVersionOutput](cfnSFNCreateContext(ctx, r, "StateMachineVersion"), h.commands, "stepfunctions", "PublishStateMachineVersion", in)
	if err != nil {
		return cfnWorkflowCreationFailure(ctx, r, h, err)
	}
	id := cfnComputeValue(out.StateMachineVersionArn)
	return cfnWorkflowResult(id, id, id), nil
}
func (h cfnStateMachineVersion) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeChanged(r.Previous, r.Properties, "StateMachineArn", "StateMachineRevisionId", "Description") {
		return cloudformation.ResourceResult{}, fmt.Errorf("state machine versions are immutable")
	}
	_, err := h.Read(cfnSFNContext(ctx, r, "StateMachineVersion"), r)
	return cfnWorkflowResult(r.PhysicalID, r.PhysicalID, r.PhysicalID), err
}
func (h cfnStateMachineVersion) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return err
	}
	return cfnSFNAbsent(cfnComputeRun(cfnSFNContext(ctx, r, "StateMachineVersion"), h.commands, "stepfunctions", "DeleteStateMachineVersion", map[string]any{"StateMachineVersionArn": r.PhysicalID}))
}
func (h cfnStateMachineVersion) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.DescribeStateMachineOutput](ctx, h.commands, "stepfunctions", "DescribeStateMachine", map[string]any{"StateMachineArn": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	at := strings.LastIndex(r.PhysicalID, ":")
	if at < 0 {
		return nil, fmt.Errorf("invalid version ARN")
	}
	p := cloudformation.Properties{"Arn": r.PhysicalID, "StateMachineArn": r.PhysicalID[:at], "StateMachineRevisionId": cfnComputeValue(out.RevisionId)}
	if out.Description != nil {
		p["Description"] = cfnComputeValue(out.Description)
	}
	return p, nil
}
func (h cfnStateMachineVersion) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	machines, err := cfnSFNMachineIDs(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, machine := range machines {
		in := map[string]any{"StateMachineArn": machine}
		for {
			out, err := cfnComputeCall[api.ListStateMachineVersionsOutput](ctx, h.commands, "stepfunctions", "ListStateMachineVersions", in)
			if err != nil {
				return nil, err
			}
			for _, row := range out.StateMachineVersions {
				rr := r
				rr.PhysicalID = cfnComputeValue(row.StateMachineVersionArn)
				p, err := h.Read(ctx, rr)
				if err != nil {
					return nil, err
				}
				result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			in["NextToken"] = cfnComputeValue(out.NextToken)
		}
	}
	return result, nil
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-stepfunctions-statemachinealias.html
type cfnStateMachineAlias struct{ commands StepFunctionsCommands }

func (h cfnStateMachineAlias) Validate(p cloudformation.Properties) error {
	if err := cfnWorkflowValidate(p, nil, "Name", "Description", "RoutingConfiguration", "DeploymentPreference", "StateMachineArn"); err != nil {
		return err
	}
	if _, err := cfnSFNAliasRouting(p); err != nil {
		return err
	}
	if arn := cfnComputeString(p, "StateMachineArn"); arn != "" && arn != cfnSFNAliasMachine(p) {
		return fmt.Errorf("StateMachineArn must match RoutingConfiguration")
	}
	return nil
}
func cfnSFNAliasRouting(p cloudformation.Properties) (any, error) {
	if routing, ok := p["RoutingConfiguration"]; ok {
		if p["DeploymentPreference"] != nil {
			return nil, fmt.Errorf("RoutingConfiguration and DeploymentPreference are mutually exclusive")
		}
		list, ok := routing.([]any)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("RoutingConfiguration must be a nonempty list")
		}
		return routing, nil
	}
	preference, ok := cfnComputeObject(p["DeploymentPreference"])
	if !ok {
		return nil, fmt.Errorf("RoutingConfiguration or DeploymentPreference is required")
	}
	if cfnComputeString(preference, "Type") != "ALL_AT_ONCE" {
		return nil, fmt.Errorf("the Step Functions owner does not support gradual alias deployments")
	}
	version := cfnComputeString(preference, "StateMachineVersionArn")
	if version == "" {
		return nil, fmt.Errorf("DeploymentPreference requires StateMachineVersionArn")
	}
	if len(preference) > 2 {
		return nil, fmt.Errorf("ALL_AT_ONCE supports only Type and StateMachineVersionArn")
	}
	return []any{map[string]any{"StateMachineVersionArn": version, "Weight": 100}}, nil
}
func cfnSFNAliasMachine(p cloudformation.Properties) string {
	routing, _ := cfnSFNAliasRouting(p)
	list, _ := routing.([]any)
	if len(list) == 0 {
		return ""
	}
	route, _ := cfnComputeObject(list[0])
	version := cfnComputeString(route, "StateMachineVersionArn")
	if at := strings.LastIndex(version, ":"); at >= 0 {
		return version[:at]
	}
	return ""
}
func (h cfnStateMachineAlias) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name") || cfnSFNAliasMachine(a) != cfnSFNAliasMachine(b), h.Validate(b)
}
func (h cfnStateMachineAlias) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	routing, err := cfnSFNAliasRouting(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnSFNName(r, "Name")
	out, err := cfnComputeCall[api.CreateStateMachineAliasOutput](cfnSFNCreateContext(ctx, r, "StateMachineAlias"), h.commands, "stepfunctions", "CreateStateMachineAlias", map[string]any{"Name": name, "Description": cfnComputeDefault(r.Properties, "Description", ""), "RoutingConfiguration": routing})
	if err != nil {
		return cfnWorkflowCreationFailure(ctx, r, h, err)
	}
	id := cfnComputeValue(out.StateMachineAliasArn)
	return cfnWorkflowResult(id, id, id), nil
}
func (h cfnStateMachineAlias) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	routing, err := cfnSFNAliasRouting(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnWorkflowResult(r.PhysicalID, r.PhysicalID, r.PhysicalID)
	return result, cfnComputeRun(cfnSFNContext(ctx, r, "StateMachineAlias"), h.commands, "stepfunctions", "UpdateStateMachineAlias", map[string]any{"StateMachineAliasArn": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", ""), "RoutingConfiguration": routing})
}
func (h cfnStateMachineAlias) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return err
	}
	return cfnSFNAbsent(cfnComputeRun(cfnSFNContext(ctx, r, "StateMachineAlias"), h.commands, "stepfunctions", "DeleteStateMachineAlias", map[string]any{"StateMachineAliasArn": r.PhysicalID}))
}
func (h cfnStateMachineAlias) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.DescribeStateMachineAliasOutput](ctx, h.commands, "stepfunctions", "DescribeStateMachineAlias", map[string]any{"StateMachineAliasArn": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	p, err := cfnSFNProjection(out, "Name", "Description", "RoutingConfiguration")
	p["Arn"] = cfnComputeValue(out.StateMachineAliasArn)
	if at := strings.LastIndex(r.PhysicalID, ":"); at >= 0 {
		p["StateMachineArn"] = r.PhysicalID[:at]
	}
	return p, err
}
func (h cfnStateMachineAlias) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	machines, err := cfnSFNMachineIDs(ctx, h.commands)
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, machine := range machines {
		in := map[string]any{"StateMachineArn": machine}
		for {
			out, err := cfnComputeCall[api.ListStateMachineAliasesOutput](ctx, h.commands, "stepfunctions", "ListStateMachineAliases", in)
			if err != nil {
				return nil, err
			}
			for _, row := range out.StateMachineAliases {
				rr := r
				rr.PhysicalID = cfnComputeValue(row.StateMachineAliasArn)
				p, err := h.Read(ctx, rr)
				if err != nil {
					return nil, err
				}
				result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			in["NextToken"] = cfnComputeValue(out.NextToken)
		}
	}
	return result, nil
}
