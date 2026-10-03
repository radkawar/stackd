package organizations

import (
	"net/http"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *operationState) handshakePermission(r *http.Request, action, id string) ([]authorization.Request, *awswire.Error) {
	m := awsctx.FromContext(r.Context())
	i, err := s.handshake(id)
	if err != nil {
		// Authorize the requested identifier before the handler reports absence.
		return []authorization.Request{{Action: "organizations:" + action, ResourceARN: "arn:" + m.Partition + ":organizations::" + m.AccountID + ":handshake/*/*/" + id}}, nil
	}
	o := s.orgs[i.OrganizationID]
	sender, recipient := i.ManagementAccountID == m.AccountID, s.invitationRecipient(i, m.AccountID)
	allowed := false
	switch action {
	case "CancelHandshake":
		allowed = sender
	case "AcceptHandshake", "DeclineHandshake":
		allowed = recipient || action == "AcceptHandshake" && i.Action == "ENABLE_ALL_FEATURES" && sender
	case "DescribeHandshake":
		allowed = sender || recipient || o != nil && o.accounts[m.AccountID].State == "ACTIVE" && len(o.delegates[m.AccountID]) > 0
	}
	if !allowed {
		return nil, failure("AccessDeniedException", "The account is not authorized for this handshake operation.")
	}
	permission := organizationPermission(o, m.Partition, m.AccountID, action, i.arn(m.Partition), nil)
	permission.ResourceARN = i.arn(m.Partition)
	permission.ResourceAccountID = i.ManagementAccountID
	if recipient && !sender {
		permission.ResourceAccountGrant = true
	}
	return []authorization.Request{permission}, nil
}
