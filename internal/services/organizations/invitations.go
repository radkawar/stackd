package organizations

import (
	"net/http"
	"strings"
	"time"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *operationState) inviteAccount(r *http.Request, in *api.InviteAccountToOrganizationInput) (*api.InviteAccountToOrganizationOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	target, kind := inputString(in.Target.Id), inputString(in.Target.Type)
	if kind != "ACCOUNT" && kind != "EMAIL" {
		return nil, failure("InvalidInputException", "INVALID_PARTY_TYPE_TARGET: Handshakes require ACCOUNT or EMAIL.")
	}
	accountID := s.invitationTarget(kind, target)
	if kind == "ACCOUNT" && (len(target) != 12 || strings.Trim(target, "0123456789") != "") {
		return nil, failure("InvalidInputException", "INVALID_PATTERN: Invalid account ID.")
	}
	if kind == "EMAIL" && !validEmail(target) {
		return nil, failure("InvalidInputException", "INVALID_EMAIL_ADDRESS_TARGET: Invalid email address.")
	}
	tags, err := mergeTags(nil, in.Tags)
	if err != nil {
		return nil, err
	}
	if kind == "ACCOUNT" && s.memberships[accountID] != "" {
		return nil, alreadyMember()
	}
	daily := 0
	for _, stored := range s.handshakes {
		invitation, visible := s.observeHandshake(stored)
		if invitation.Action != "INVITE" || invitation.OrganizationID != o.organization.ID {
			continue
		}
		if invitation.State != "ACCEPTED" && !invitation.RequestedAt.Before(s.instant.Add(-24*time.Hour)) {
			daily++
		}
		if visible && invitation.State == "OPEN" && (invitation.TargetType == kind && strings.EqualFold(invitation.Target, target) || accountID != "" && invitation.TargetAccountID == accountID) {
			return nil, failure("DuplicateHandshakeException", "An invitation to this account is already open.")
		}
	}
	if s.accountQuotaReached(o, s.accountQuota, "") {
		return nil, failure("ConstraintViolationException", "ACCOUNT_NUMBER_LIMIT_EXCEEDED: The organization has reached its account quota.")
	}
	if daily >= max(20, s.accountQuota) {
		return nil, failure("ConstraintViolationException", "HANDSHAKE_RATE_LIMIT_EXCEEDED: The daily invitation quota has been reached.")
	}
	featureSet := o.organization.FeatureSet
	if _, ok := s.featureMigration(o.organization.ID); ok {
		featureSet = "ALL"
	}
	origin := awsctx.FromContext(r.Context())
	invitation := HandshakeRecord{Action: "INVITE", ID: identifier("h-", 16), OrganizationID: o.organization.ID, ManagementAccountID: o.organization.MasterAccountID, ManagementName: o.accounts[o.organization.MasterAccountID].Name, ManagementEmail: o.accounts[o.organization.MasterAccountID].Email, FeatureSet: featureSet, TargetAccountID: accountID, TargetType: kind, Target: target, Notes: inputString(in.Notes), State: "OPEN", RequestedAt: s.instant, ExpiresAt: s.instant.Add(invitationLifetime), Tags: tags, RequestID: origin.RequestID, RequestRegion: origin.Region, ActorARN: origin.PrincipalARN}
	// TODO: Comeback deliver invitation notifications through the deferred email integration and verify email verification, billing/partition eligibility, tag-policy checks and invitation throttling against AWS.
	s.handshakes[invitation.ID] = invitation
	s.recordHandshake(invitation, origin)
	return &api.InviteAccountToOrganizationOutput{Handshake: invitation.api(s.partition)}, nil
}

func (s *serviceState) invitationTarget(kind, target string) string {
	if kind == "ACCOUNT" {
		return target
	}
	if id := s.knownEmails[strings.ToLower(target)]; id != "" {
		return id
	}
	// Bootstrap roots have an account-owned local address, including before the
	// first account-setting write registers their identity.
	id, ok := strings.CutSuffix(strings.ToLower(target), "@localhost.local")
	if ok && len(id) == 12 && strings.Trim(id, "0123456789") == "" {
		return id
	}
	return ""
}

func (s *serviceState) invitationRecipient(i HandshakeRecord, accountID string) bool {
	if o := s.orgs[s.memberships[accountID]]; o != nil && o.organization.MasterAccountID == accountID {
		return false
	}
	if i.TargetAccountID != "" {
		return i.TargetAccountID == accountID
	}
	a, ok := s.knownAccounts[accountID]
	if !ok {
		a = bootstrapAccount(accountID)
	}
	return i.TargetType == "EMAIL" && strings.EqualFold(i.Target, a.Email)
}

func alreadyMember() *awswire.Error {
	return failure("HandshakeConstraintViolationException", "ALREADY_IN_AN_ORGANIZATION: The AWS account is already a member of an organization.")
}
