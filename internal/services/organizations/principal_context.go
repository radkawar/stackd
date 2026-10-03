package organizations

import (
	"context"
	"slices"
	"strings"

	"stackd/internal/awsctx"
)

// PrincipalOrganization returns the caller's organization and OU ancestry from
// the same detached snapshot used by signed-session policy decisions.
func (s *Service) PrincipalOrganization(ctx context.Context) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	m := awsctx.FromContext(ctx)
	if snapshot, ok := ctx.Value(policySnapshotKey{}).(policySnapshot); ok && snapshot.source == s && snapshot.partition == m.Partition && snapshot.account == m.AccountID {
		return snapshot.organization, snapshot.path, nil
	}
	record, _, err := s.storage.Load(ctx, m.Partition)
	if err != nil {
		return "", "", err
	}
	worker := &operationState{serviceState: decodeState(record, m.Partition, m.AccountID)}
	id, path := worker.principalOrganization(m.AccountID)
	return id, path, nil
}

func (s *operationState) principalOrganization(accountID string) (string, string) {
	o := s.orgs[s.memberships[accountID]]
	if o == nil {
		return "", ""
	}
	return o.organization.ID, o.entityPath(o.parents[accountID])
}

// entityPath includes the selected entity and the trailing slash used by the
// Organizations API. IAM principal paths select the account's parent instead.
func (o *orgState) entityPath(target string) string {
	var ancestors []string
	for ; target != ""; target = o.parents[target] {
		ancestors = append(ancestors, target)
	}
	ancestors = append(ancestors, o.organization.ID)
	slices.Reverse(ancestors)
	return strings.Join(ancestors, "/") + "/"
}

func (s *operationState) callerPolicySnapshot(source *Service) policySnapshot {
	id, path := s.principalOrganization(s.caller)
	return policySnapshot{source: source, partition: s.partition, account: s.caller, levels: s.policyLevels(s.caller), organization: id, path: path}
}
