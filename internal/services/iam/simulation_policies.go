package iam

import (
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// A simulation policy retains its owner and document separately. Exclusion
// selectors and result attribution must not lose the source when policies from
// a user's groups are combined with its own policies.
type simulationPolicy struct {
	permissionPolicySource
	sourceType iamapi.PolicySourceType
	sourceID   string
	boundary   bool
}

type simulationPrincipal struct {
	arn, kind, name, id string
	policies            []simulationPolicy
	boundary            *simulationPolicy
	serviceLinked       bool
}

func simulationPrincipalPolicies(a *account, m awsctx.Metadata, arn string) (simulationPrincipal, *awswire.Error) {
	identity, apiErr := resolvePermissionPolicyIdentity(a, m, arn)
	if apiErr != nil {
		return simulationPrincipal{}, apiErr
	}
	result := simulationPrincipal{arn: identity.arn, kind: identity.kind, name: identity.name, id: identity.id, serviceLinked: identity.serviceLinked}
	sources, apiErr := permissionPolicySources(a, identity.owners)
	if apiErr != nil {
		return result, apiErr
	}
	for _, source := range sources {
		result.policies = append(result.policies, simulationPolicySource(source))
	}
	boundary := identity.boundary
	if boundary != nil {
		policy, apiErr := simulationManagedPolicy(a, boundary.PermissionsBoundaryArn)
		if apiErr != nil {
			return result, apiErr
		}
		policy.boundary = true
		result.boundary = &policy
	}
	return result, nil
}

func simulationManagedPolicy(a *account, arn string) (simulationPolicy, *awswire.Error) {
	source, apiErr := managedPermissionPolicySource(a, arn)
	if apiErr != nil {
		return simulationPolicy{}, apiErr
	}
	return simulationPolicySource(source), nil
}

func simulationPolicySource(source permissionPolicySource) simulationPolicy {
	kind := iamapi.PolicySourceType(source.ownerKind)
	id := source.ownerKind + "_" + source.ownerName + "_" + source.name
	if source.arn != "" {
		kind = iamapi.PolicySourceTypeUSER_MANAGED
		if parts := strings.SplitN(source.arn, ":", 6); len(parts) == 6 && parts[4] == "aws" {
			kind = iamapi.PolicySourceTypeAWS_MANAGED
		}
		id = source.name
	}
	return simulationPolicy{permissionPolicySource: source, sourceID: id, sourceType: kind}
}
