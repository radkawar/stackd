package iam

import (
	"context"
	"fmt"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func simulateCustomPolicy(ctx context.Context, _ *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, apiErr := generatedIAMInput[iamapi.SimulateCustomPolicyRequest](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	return runSimulation(ctx, m, "SimulateCustomPolicy", *input, simulationPrincipal{}, nil)
}

func (s *Service) simulatePrincipalPolicy(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	input, apiErr := generatedIAMInput[iamapi.SimulatePrincipalPolicyRequest](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	principal, apiErr := simulationPrincipalPolicies(a, m, inputString(input.PolicySourceArn))
	if apiErr != nil {
		return nil, apiErr
	}
	exclusions, apiErr := simulationExclusions(input.PolicyExclusionList)
	if apiErr != nil {
		return nil, apiErr
	}
	retained := principal.policies[:0]
	for _, policy := range principal.policies {
		if !simulationPolicyExcluded(policy, exclusions) {
			retained = append(retained, policy)
		}
	}
	principal.policies = retained
	if principal.boundary != nil && simulationPolicyExcluded(*principal.boundary, exclusions) {
		principal.boundary = nil
	}
	common := iamapi.SimulateCustomPolicyRequest{
		ActionNames: input.ActionNames, CallerArn: input.CallerArn, ContextEntries: input.ContextEntries,
		Marker: input.Marker, MaxItems: input.MaxItems, PolicyInputList: input.PolicyInputList,
		PermissionsBoundaryPolicyInputList: input.PermissionsBoundaryPolicyInputList,
		ResourceArns:                       input.ResourceArns, ResourceHandlingOption: input.ResourceHandlingOption,
		ResourceOwner: input.ResourceOwner, ResourcePolicy: input.ResourcePolicy,
	}
	if common.CallerArn == nil {
		common.CallerArn = wirePointer(iamapi.ResourceNameType(principal.arn))
	}
	var controls [][]string
	if s.simulationControls != nil && !principal.serviceLinked && !simulationExcludesControls(exclusions) {
		levels, err := s.simulationControls.ServiceControlPolicies(ctx)
		if err != nil {
			return nil, &awswire.Error{Code: "PolicyEvaluation", Message: "Unable to load organization policies.", StatusCode: 500}
		}
		for _, level := range levels {
			documents := make([]string, 0, len(level.Documents))
			for _, p := range level.Documents {
				documents = append(documents, p.Document)
			}
			controls = append(controls, documents)
		}
	}
	return runSimulation(ctx, m, "SimulatePrincipalPolicy", common, principal, controls)
}

func runSimulation(ctx context.Context, m awsctx.Metadata, operation string, input iamapi.SimulateCustomPolicyRequest, principal simulationPrincipal, controls [][]string) (any, *awswire.Error) {
	for i, document := range input.PolicyInputList {
		principal.policies = append(principal.policies, simulationPolicy{permissionPolicySource: permissionPolicySource{document: string(document)}, sourceID: fmt.Sprintf("PolicyInputList.%d", i+1)})
	}
	if len(input.PermissionsBoundaryPolicyInputList) > 1 {
		return nil, invalidInput("The list of Permissions Boundary policies cannot exceed 1 items.")
	}
	if len(input.PermissionsBoundaryPolicyInputList) == 1 {
		principal.boundary = &simulationPolicy{permissionPolicySource: permissionPolicySource{document: string(input.PermissionsBoundaryPolicyInputList[0])}, sourceID: "PermissionsBoundaryPolicyInputList.1", boundary: true}
	}
	for i, level := range input.OrderedOrganizationPolicyInputList {
		if len(level.ServiceControlPolicyInputList) == 0 {
			return nil, invalidInput(fmt.Sprintf("Organization policy at index %d must contain at least one service control policy", i+1))
		}
		controls = append(controls, simulationStrings(level.ServiceControlPolicyInputList))
	}
	simulation, apiErr := compileSimulation(input, m, principal, controls)
	if apiErr != nil {
		return nil, apiErr
	}
	start, end, apiErr := simulationPage(m, operation, input.Marker, input.MaxItems, len(input.ActionNames))
	if apiErr != nil {
		return nil, apiErr
	}
	output := iamapi.SimulatePolicyResponse{EvaluationResults: iamapi.EvaluationResultsListType{}, IsTruncated: wirePointer(iamapi.BooleanType(end < len(input.ActionNames)))}
	for _, action := range input.ActionNames[start:end] {
		if err := ctx.Err(); err != nil {
			return nil, simulationError(err)
		}
		result, apiErr := simulation.evaluate(string(action))
		if apiErr != nil {
			return nil, apiErr
		}
		output.EvaluationResults = append(output.EvaluationResults, result)
	}
	if end < len(input.ActionNames) {
		output.Marker = wirePointer(iamapi.ResponseMarkerType(simulationMarker(m, operation, end)))
	}
	return &output, nil
}

func simulationStrings[T ~[]E, E ~string](values T) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}
