package organizations

import (
	"context"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

// ResourceControlPolicies returns the resource owner's RCP hierarchy. The
// owner can belong to a different organization than the authenticated caller.
// An IAM-borrowed transaction keeps these reads stable through session issuance.
func (s *Service) ResourceControlPolicies(ctx context.Context, accountID string) (authorization.ResourceControlSet, error) {
	var result authorization.ResourceControlSet
	if err := ctx.Err(); err != nil {
		return result, err
	}
	m := awsctx.FromContext(ctx)
	// TODO: Comeback model RCP attachment/detachment propagation in service time after capturing AWS transition timing; authorization currently reads committed policy state immediately.
	record, _, err := s.storage.Load(ctx, m.Partition)
	if err != nil {
		return result, err
	}
	state := decodeState(record, m.Partition, accountID)
	worker := &operationState{serviceState: state}
	result.OrganizationID, result.OrganizationPath = worker.principalOrganization(accountID)
	o := state.orgs[state.memberships[accountID]]
	if o == nil || o.organization.MasterAccountID == accountID || !o.policyEnabled("RESOURCE_CONTROL_POLICY") {
		return result, nil
	}
	result.Levels = o.controlPolicyLevels(accountID, "RESOURCE_CONTROL_POLICY")
	return result, nil
}
