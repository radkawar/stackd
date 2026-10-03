package organizations

import (
	"context"
	"maps"
	"slices"
)

// RoleInspector holds the IAM transaction while Organizations evaluates and
// commits a migration. Presence reports the protected Organizations service role
// in each requested account. The callback must join that transaction through ctx;
// errors roll back its changes. No external effects run inside the callback.
type RoleInspector interface {
	WithOrganizationServiceRoles(context.Context, string, []string, func(context.Context, map[string]bool) error) error
}

// SetRoleInspector connects authoritative IAM role inspection before serving.
func (s *Service) SetRoleInspector(roles RoleInspector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roleInspector = roles
}

func (s *operationState) roleCheckAccounts(action string, input any) []string {
	o := s.orgs[s.memberships[s.caller]]
	if action == "AcceptHandshake" {
		id := inputString(input.(interface{ ResourceHandshakeID() *string }).ResourceHandshakeID())
		h := s.handshakes[id]
		if h.Action != "ENABLE_ALL_FEATURES" {
			return nil
		}
		o = s.orgs[h.OrganizationID]
	} else if action != "EnableAllFeatures" {
		return nil
	}
	if o == nil || o.organization.FeatureSet == "ALL" {
		return nil
	}
	return slices.Sorted(maps.Keys(o.accounts))
}
