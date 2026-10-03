package organizations

import (
	"stackd/internal/awsctx"
	"stackd/journal"
)

func (s *operationState) recordHandshake(i HandshakeRecord, origin awsctx.Metadata) {
	at := s.instant
	if !i.pending() {
		at = i.TerminalAt
	}
	s.events = append(s.events, journal.Event{
		Envelope:         journal.Envelope{At: at, Partition: s.partition, AccountID: i.ManagementAccountID, Region: origin.Region, RequestID: origin.RequestID, ActorARN: origin.PrincipalARN},
		HandshakeChanged: journal.HandshakeChanged{Action: i.Action, ParentID: i.ParentID, OrganizationID: i.OrganizationID, HandshakeID: i.ID, TargetAccountID: i.TargetAccountID, State: i.State},
	})
}
