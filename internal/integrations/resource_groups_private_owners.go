package integrations

import (
	"context"

	"stackd/internal/services/cloudformation"
)

// The ledger selects candidates only. Every entry in owned is proved against
// a current typed native record in the coordinated read snapshot, independently
// of public tags. Unsupported or unclaimed native records remain absent.
type resourceGroupsPrivateOwners struct {
	requests map[string]cloudformation.ResourceRequest
	owned    map[string]bool
}

func (o *resourceGroupsPrivateOwners) needs(types ...string) bool {
	for _, request := range o.requests {
		for _, kind := range types {
			if request.Type == kind {
				return true
			}
		}
	}
	return false
}

func (o *resourceGroupsPrivateOwners) claim(resourceARN, actual string, expected func(cloudformation.ResourceRequest) string) {
	request, found := o.requests[resourceARN]
	if found && actual != "" && actual == expected(request) {
		o.owned[resourceARN] = true
	}
}

func (o *resourceGroupsPrivateOwners) structured(resourceARN, stackID, logicalID, token string) {
	request, found := o.requests[resourceARN]
	if found && stackID != "" && logicalID != "" && token != "" && request.StackID == stackID && request.LogicalID == logicalID && request.Token == token {
		o.owned[resourceARN] = true
	}
}

func (r ResourceGroupsResources) privateOwners(ctx context.Context, stack cloudformation.StackRecord, candidates []cloudformation.ResourceRecord) (map[string]bool, error) {
	owners := resourceGroupsPrivateOwners{requests: make(map[string]cloudformation.ResourceRequest), owned: make(map[string]bool)}
	for _, candidate := range candidates {
		_, eligible := resourceGroupsEligibility(candidate.Type)
		if !eligible || !candidate.Current || candidate.PhysicalID == "" || candidate.Status == "DELETE_COMPLETE" || candidate.Token == "" || candidate.LogicalID == "" || resourceGroupsLambdaStackOnly(candidate.Type) || candidate.Type == "AWS::KMS::Alias" || candidate.Type == "AWS::CloudFormation::Stack" {
			continue
		}
		resourceARN := resourceGroupsStackARN(stack.Scope, candidate)
		if resourceARN == "" {
			continue
		}
		owners.requests[resourceARN] = cloudformation.ResourceRequest{Scope: stack.Scope, StackID: stack.ID, StackName: stack.Name, LogicalID: candidate.LogicalID, Type: candidate.Type, PhysicalID: candidate.PhysicalID, Token: candidate.Token, Properties: candidate.Properties}
	}
	for _, project := range []func(context.Context, cloudformation.Scope, *resourceGroupsPrivateOwners) error{r.privateCoreOwners, r.privateComputeOwners, r.privateDataOwners, r.privateGovernanceOwners, r.privateSourceOwners} {
		if err := project(ctx, stack.Scope, &owners); err != nil {
			return nil, err
		}
	}
	return owners.owned, nil
}
