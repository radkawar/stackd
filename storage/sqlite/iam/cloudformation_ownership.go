package iam

import (
	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
	"strings"
)

// Ownership columns travel with the existing native identity and relationship
// rows. Empty UserToGroupAddition resources additionally need a native claim.
func (r reader) readGroupCFN(scope domain.Scope, key string, record *domain.Group) error {
	claims, err := r.q.ReadGroupMembershipClaims(r.ctx, sqlcgen.ReadGroupMembershipClaimsParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(key)})
	if err != nil {
		return err
	}
	if len(claims) > 0 {
		record.MembershipClaims = make(map[string]struct{}, len(claims))
		for _, owner := range claims {
			record.MembershipClaims[owner] = struct{}{}
		}
	}
	return nil
}
func (w writer) writeGroupCFN(scope domain.Scope, record domain.Group) error {
	for owner := range record.MembershipClaims {
		if err := w.q.WriteGroupMembershipClaim(w.ctx, sqlcgen.WriteGroupMembershipClaimParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: strings.ToLower(record.GroupName), Owner: owner}); err != nil {
			return err
		}
	}
	return nil
}
