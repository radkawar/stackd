package organizations

import (
	"context"
	"fmt"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// AccountManagementPermission resolves Organizations-mode Account requests.
// Account calls this inside its shared transaction before IAM authorization;
// trusted access, delegated administration, target membership and IAM policy
// decisions therefore cannot race the resulting account-setting mutation.
func (s *Service) AccountManagementPermission(ctx context.Context, target, action string) (authorization.Request, error) {
	m := awsctx.FromContext(ctx)
	denied := func(reason string) (authorization.Request, error) {
		message := fmt.Sprintf("User: %s is not authorized to perform: %s", m.PrincipalARN, action)
		if reason != "" {
			message += " (" + reason + ")"
		}
		return authorization.Request{}, &awswire.Error{Code: "AccessDeniedException", Message: message, StatusCode: 403}
	}
	record, _, err := s.storage.Load(ctx, m.Partition)
	if err != nil {
		return authorization.Request{}, err
	}
	state := &operationState{serviceState: decodeState(record, m.Partition, m.AccountID)}
	o := state.orgs[state.memberships[m.AccountID]]
	if o == nil {
		return denied("")
	}
	management := o.organization.MasterAccountID == m.AccountID
	_, delegated := o.delegates[m.AccountID]["account.amazonaws.com"]
	if !management && !delegated {
		return denied("")
	}
	if _, trusted := o.services["account.amazonaws.com"]; !trusted {
		return denied("Your organization must first enable trusted access with AWS Account Management.")
	}
	targetAccount, member := o.accounts[target]
	if target == o.organization.MasterAccountID && strings.Contains(action, "PrimaryEmail") {
		return denied("Access Denied")
	}
	if o.organization.FeatureSet != "ALL" || o.accounts[m.AccountID].State != "ACTIVE" || !member || (targetAccount.State != "ACTIVE" && action != "account:GetAccountInformation") || target == o.organization.MasterAccountID {
		return denied("")
	}
	arn := fmt.Sprintf("arn:%s:account::%s:account/%s/%s", m.Partition, o.organization.MasterAccountID, o.organization.ID, target)
	_, path := state.principalOrganization(target)
	permission := authorization.Request{Action: action, ResourceARN: arn, Context: map[string][]string{"account:AccountResourceOrgPaths": {path}}}
	for key, val := range o.tags[target] {
		permission.Context["account:AccountResourceOrgTags/"+key] = []string{val}
	}
	if !management {
		// This account-level grant supplies the verified service delegation across
		// accounts. The caller still needs identity permission, boundary, session
		// permission and its applicable SCP hierarchy.
		permission.ResourcePolicies = []authorization.BoundPolicy{{Document: fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:%s:iam::%s:root"},"Action":%q,"Resource":%q}]}`, m.Partition, m.AccountID, action, arn)}}
	}
	return permission, nil
}
