package organizations

import (
	"strings"
	"time"
)

const invitationLifetime = 15 * 24 * time.Hour
const featureMigrationLifetime = 90 * 24 * time.Hour

const handshakeRetention = 30 * 24 * time.Hour

// HandshakeRecord retains membership offers and feature consent independently of
// the organization. TargetType/Target preserve an invitation's original address;
// TargetAccountID binds its resolved account. Tags apply on membership acceptance.
// ParentID relates feature requests to their migration. Approvals retains each
// required account's pending/accepted consent after child history expires.
type HandshakeRecord struct {
	ID, OrganizationID, ManagementAccountID     string
	ManagementName, ManagementEmail, FeatureSet string
	TargetAccountID, TargetType, Target, Notes  string
	Action, ParentID                            string
	Approvals                                   map[string]bool
	State                                       string
	RequestedAt, ExpiresAt, TerminalAt          time.Time
	RequestID, RequestRegion, ActorARN          string
	Tags                                        map[string]string
}

func (i HandshakeRecord) arn(partition string) string {
	return "arn:" + partition + ":organizations::" + i.ManagementAccountID + ":handshake/" + i.OrganizationID + "/" + strings.ToLower(i.Action) + "/" + i.ID
}

func (i HandshakeRecord) observed(now time.Time) (HandshakeRecord, bool) {
	if i.pending() && !now.Before(i.ExpiresAt) {
		i.State, i.TerminalAt = "EXPIRED", i.ExpiresAt
	}
	return i, i.pending() || now.Before(i.TerminalAt.Add(handshakeRetention))
}

func (i HandshakeRecord) pending() bool { return i.State == "OPEN" || i.State == "REQUESTED" }
