package organizations

import (
	"stackd/internal/awsctx"
	"stackd/journal"
)

func (s *operationState) recordEffectivePolicy(o *orgState, p EffectivePolicyRecord, state journal.EffectivePolicyState, origin awsctx.Metadata) {
	s.events = append(s.events, journal.Event{
		Envelope:               journal.Envelope{At: s.instant, Partition: s.partition, AccountID: o.organization.MasterAccountID, Region: origin.Region, RequestID: origin.RequestID, ActorARN: origin.PrincipalARN},
		EffectivePolicyChanged: journal.EffectivePolicyChanged{OrganizationID: o.organization.ID, TargetAccountID: p.AccountID, PolicyType: p.PolicyType, State: state},
	})
}
