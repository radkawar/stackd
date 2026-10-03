package organizations

import (
	"net/http"
	"strings"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *operationState) acceptHandshake(r *http.Request, in *api.AcceptHandshakeInput) (*api.AcceptHandshakeOutput, *awswire.Error) {
	i, err := s.handshake(inputString(in.HandshakeId))
	if err != nil {
		return nil, err
	}
	if err = handshakeTransition(i, "ACCEPTED"); err != nil {
		return nil, err
	}
	if i.Action != "INVITE" {
		return s.acceptFeatureHandshake(r, i)
	}
	m := awsctx.FromContext(r.Context())
	o := s.orgs[i.OrganizationID]
	if o == nil {
		return nil, failure("InvalidHandshakeTransitionException", "The inviting organization no longer exists.")
	}
	if s.memberships[m.AccountID] != "" {
		// Native AWS consumes the email handshake even though joining fails. Commit
		// that terminal transition before returning the modeled membership error.
		s.finishHandshake(r, i, "ACCEPTED")
		s.afterCommitError = alreadyMember()
		return &api.AcceptHandshakeOutput{}, nil
	}
	if s.accountQuotaReached(o, s.accountQuota, i.ID) {
		return nil, failure("HandshakeConstraintViolationException", "ACCOUNT_NUMBER_LIMIT_EXCEEDED: The organization has reached its account quota.")
	}
	a, ok := s.knownAccounts[m.AccountID]
	if !ok {
		a = bootstrapAccount(m.AccountID)
	}
	// TODO: Comeback capture native standalone acceptance, dependency failures and outstanding-invitation behavior; audit billing/partition eligibility, account-state failure reasons and organization-deletion interactions before claiming full membership conformance.
	a.ARN, a.JoinedMethod, a.JoinedTimestamp = o.arn(s.partition, "account", a.ID), "INVITED", s.timestamp()
	o.accounts[a.ID], s.knownAccounts[a.ID] = a, a
	o.parents[a.ID], o.tags[a.ID] = o.root.ID, i.Tags
	o.attachDefaults(a.ID)
	s.scheduleEffectivePolicies(o, []string{a.ID}, "", m)
	s.memberships[a.ID], s.knownEmails[strings.ToLower(a.Email)] = i.OrganizationID, a.ID
	s.accountProvisioning = &AccountProvisioning{Partition: s.partition, AccountID: a.ID, ManagementAccountID: i.ManagementAccountID, CreatedAt: s.instant}
	if i.FeatureSet == "ALL" {
		s.approveFeatureMigration(r, o, a.ID)
	}
	i = s.finishHandshake(r, i, "ACCEPTED")
	return &api.AcceptHandshakeOutput{Handshake: i.api(s.partition)}, nil
}
