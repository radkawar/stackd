package organizations

import (
	"maps"
	"net/http"
	"slices"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *operationState) enableAllFeatures(r *http.Request, _ *api.EnableAllFeaturesInput) (*api.EnableAllFeaturesOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if o.organization.FeatureSet == "ALL" {
		return nil, failure("HandshakeConstraintViolationException", "ORGANIZATION_ALREADY_HAS_ALL_FEATURES: All features are already enabled on this organization.")
	}
	if _, ok := s.featureMigration(o.organization.ID); ok {
		return nil, failure("HandshakeConstraintViolationException", "ORGANIZATION_IS_ALREADY_PENDING_ALL_FEATURES_MIGRATION: An all-features migration is already pending.")
	}
	if len(o.accounts) > 5000 {
		return nil, failure("ConstraintViolationException", "ALL_FEATURES_MIGRATION_ORGANIZATION_SIZE_LIMIT_EXCEEDED: Standard migration supports at most 5000 accounts.")
	}
	// TODO: Comeback capture a native standard migration including resend, cancellation/expiry, concurrent membership/role changes, policy availability and error precedence; AWS's API prose and worked CLI examples disagree on parent/child action names. Deliver feature-consent notifications through the deferred email integration. Assisted migration remains outside this API.
	origin := awsctx.FromContext(r.Context())
	parent := s.newFeatureHandshake(o, "ENABLE_ALL_FEATURES", "", "", origin)
	parent.Approvals = make(map[string]bool)
	var children []HandshakeRecord
	for _, id := range slices.Sorted(maps.Keys(o.accounts)) {
		if id == o.organization.MasterAccountID {
			continue
		}
		action := ""
		if o.accounts[id].JoinedMethod == "INVITED" {
			action = "APPROVE_ALL_FEATURES"
		} else if !s.serviceRoles[id] {
			action = "ADD_ORGANIZATIONS_SERVICE_LINKED_ROLE"
		}
		if action != "" {
			children = append(children, s.newFeatureHandshake(o, action, parent.ID, id, origin))
			parent.Approvals[id] = false
		}
	}
	if len(children) > 0 {
		parent.State = "REQUESTED"
	}
	// Only invitations issued for consolidated billing become stale. Invites made
	// during the migration explicitly ask the new account to accept all features.
	for _, id := range slices.Sorted(maps.Keys(s.handshakes)) {
		i := s.handshakes[id]
		if i.OrganizationID == o.organization.ID && i.Action == "INVITE" && i.pending() && s.instant.Before(i.ExpiresAt) {
			s.finishHandshake(r, i, "CANCELED")
		}
	}
	s.handshakes[parent.ID] = parent
	s.recordHandshake(parent, origin)
	for _, i := range children {
		s.handshakes[i.ID] = i
		s.recordHandshake(i, origin)
	}
	return &api.EnableAllFeaturesOutput{Handshake: parent.api(s.partition)}, nil
}

func (s *operationState) newFeatureHandshake(o *orgState, action, parent, account string, origin awsctx.Metadata) HandshakeRecord {
	return HandshakeRecord{ID: identifier("h-", 16), OrganizationID: o.organization.ID, ManagementAccountID: o.organization.MasterAccountID, Action: action, ParentID: parent, TargetAccountID: account, State: "OPEN", RequestedAt: s.instant, ExpiresAt: s.instant.Add(featureMigrationLifetime), RequestID: origin.RequestID, RequestRegion: origin.Region, ActorARN: origin.PrincipalARN}
}

func (s *operationState) featureMigration(orgID string) (HandshakeRecord, bool) {
	for _, i := range s.handshakes {
		if i.Action == "ENABLE_ALL_FEATURES" && i.OrganizationID == orgID && i.pending() && s.instant.Before(i.ExpiresAt) {
			return i, true
		}
	}
	return HandshakeRecord{}, false
}

func (s *operationState) approveFeatureMigration(r *http.Request, o *orgState, account string) {
	parent, ok := s.featureMigration(o.organization.ID)
	if !ok {
		return
	}
	if parent.Approvals == nil {
		parent.Approvals = make(map[string]bool)
	}
	parent.Approvals[account] = true
	s.handshakes[parent.ID] = parent
	s.refreshFeatureMigration(r, o)
}

func (s *operationState) refreshFeatureMigration(r *http.Request, o *orgState) {
	parent, ok := s.featureMigration(o.organization.ID)
	if !ok {
		return
	}
	for id, approved := range parent.Approvals {
		if _, member := o.accounts[id]; member && !approved {
			return
		}
	}
	if parent.State == "REQUESTED" {
		s.finishHandshake(r, parent, "OPEN")
	}
}

func (s *operationState) acceptFeatureHandshake(r *http.Request, i HandshakeRecord) (*api.AcceptHandshakeOutput, *awswire.Error) {
	o := s.orgs[i.OrganizationID]
	if o == nil {
		return nil, failure("InvalidHandshakeTransitionException", "The organization no longer exists.")
	}
	switch i.Action {
	case "APPROVE_ALL_FEATURES", "ADD_ORGANIZATIONS_SERVICE_LINKED_ROLE":
		parent, ok := s.featureMigration(o.organization.ID)
		if !ok || parent.ID != i.ParentID || s.memberships[i.TargetAccountID] != o.organization.ID {
			return nil, failure("InvalidHandshakeTransitionException", "The migration or membership is no longer active.")
		}
		s.accountProvisioning = &AccountProvisioning{Partition: s.partition, AccountID: i.TargetAccountID, ManagementAccountID: i.ManagementAccountID, CreatedAt: s.instant}
		i = s.finishHandshake(r, i, "ACCEPTED")
		s.approveFeatureMigration(r, o, i.TargetAccountID)
	case "ENABLE_ALL_FEATURES":
		for id := range o.accounts {
			if !s.serviceRoles[id] {
				return nil, failure("HandshakeConstraintViolationException", "LEGACY_PERMISSIONS_STILL_IN_USE: Every account must restore its Organizations service-linked role before finalization.")
			}
		}
		o.organization.FeatureSet = "ALL"
		// Migration makes policy types available. Enabling a root policy type is a
		// separate API transition, unlike creating a new all-features organization.
		o.organization.AvailablePolicyTypes = []policyType{{Type: "SERVICE_CONTROL_POLICY", Status: "ENABLED"}}
		i = s.finishHandshake(r, i, "ACCEPTED")
	default:
		return nil, failure("InvalidHandshakeTransitionException", "Unsupported handshake transition.")
	}
	return &api.AcceptHandshakeOutput{Handshake: i.api(s.partition)}, nil
}

func (s *operationState) cancelFeatureChildren(parent HandshakeRecord, origin awsctx.Metadata) {
	for _, id := range slices.Sorted(maps.Keys(s.handshakes)) {
		i := s.handshakes[id]
		if !i.pending() {
			continue
		}
		if belongsToMigration(i, parent) && !i.ExpiresAt.Before(parent.TerminalAt) {
			i.State, i.TerminalAt = "CANCELED", parent.TerminalAt
			s.handshakes[id] = i
			s.recordHandshake(i, origin)
		}
	}
}

// Member consent uses an explicit parent. Membership invitations made during a
// migration carry the offered feature set and its request interval.
func belongsToMigration(i, parent HandshakeRecord) bool {
	return i.ParentID == parent.ID || i.Action == "INVITE" && i.OrganizationID == parent.OrganizationID && i.FeatureSet == "ALL" && !i.RequestedAt.Before(parent.RequestedAt) && i.RequestedAt.Before(parent.ExpiresAt)
}

func (s *operationState) observeHandshake(i HandshakeRecord) (HandshakeRecord, bool) {
	if i.pending() {
		if i.ParentID != "" {
			i = s.observeMigrationMember(i, s.handshakes[i.ParentID])
		} else if i.Action == "INVITE" && i.FeatureSet == "ALL" {
			for _, parent := range s.handshakes {
				i = s.observeMigrationMember(i, parent)
			}
		}
	}
	return i.observed(s.instant)
}

func (s *operationState) observeMigrationMember(i, parent HandshakeRecord) HandshakeRecord {
	if parent.Action == "ENABLE_ALL_FEATURES" && parent.pending() && !s.instant.Before(parent.ExpiresAt) && belongsToMigration(i, parent) && !i.ExpiresAt.Before(parent.ExpiresAt) {
		i.State, i.TerminalAt = "CANCELED", parent.ExpiresAt
	}
	return i
}

func (s *operationState) removeFeatureAccount(r *http.Request, o *orgState, account string) {
	parent, ok := s.featureMigration(o.organization.ID)
	if !ok {
		return
	}
	for _, id := range slices.Sorted(maps.Keys(s.handshakes)) {
		child := s.handshakes[id]
		if child.ParentID == parent.ID && child.TargetAccountID == account && child.pending() {
			s.finishHandshake(r, child, "CANCELED")
		}
	}
	s.refreshFeatureMigration(r, o)
}
