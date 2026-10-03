package organizations

import (
	"maps"
	"slices"
	"strings"
	"time"

	"stackd/internal/awswire"
	"stackd/journal"
)

// operationState owns the mutable domain state for one authorized request.
// It has no storage or authorization handles, so domain methods cannot bypass
// the revision check or call another service while holding storage locks.
type operationState struct {
	serviceRoles map[string]bool
	*serviceState
	tokenKey            [32]byte
	instant             time.Time
	accountQuota        int
	accountProvisioning *AccountProvisioning
	events              []journal.Event
	afterCommitError    *awswire.Error
	auditOutput         any
	auditCall           *journal.APICallCompleted
}

// serviceState is an operation-owned working set. Only Storage is authoritative.
type serviceState struct {
	orgs              map[string]*orgState
	memberships       map[string]string
	knownEmails       map[string]string
	knownAccounts     map[string]account
	handshakes        map[string]HandshakeRecord
	nextAccount       uint64
	partition, caller string
	createdResourceID string
}

func decodeState(record PartitionRecord, partition, caller string) *serviceState {
	st := &serviceState{orgs: make(map[string]*orgState), memberships: make(map[string]string), knownEmails: make(map[string]string), knownAccounts: make(map[string]account), handshakes: make(map[string]HandshakeRecord), nextAccount: record.AccountSequence, partition: partition, caller: caller}
	for _, invitation := range record.Handshakes {
		st.handshakes[invitation.ID] = invitation
	}
	for _, a := range record.Accounts {
		st.knownAccounts[a.ID] = a
		st.knownEmails[strings.ToLower(a.Email)] = a.ID
	}
	for _, record := range record.Organizations {
		o := &orgState{organization: record.Organization, resourcePolicy: record.ResourcePolicy, root: record.Root, rootAccess: record.RootAccess, accounts: make(map[string]account), units: make(map[string]organizationalUnit), parents: make(map[string]string), creations: make(map[string]AccountCreationRecord), policies: make(map[string]policy), attachments: make(map[string][]string), tags: make(map[string]map[string]string), services: make(map[string]float64), delegates: make(map[string]map[string]float64)}
		for _, a := range record.Accounts {
			o.accounts[a.ID] = a
			st.memberships[a.ID] = o.organization.ID
		}
		for _, u := range record.Units {
			o.units[u.ID] = u
		}
		for _, p := range record.Parents {
			o.parents[p.ChildID] = p.ParentID
		}
		for _, c := range record.Creations {
			o.creations[c.ID] = c
		}
		for _, p := range record.Policies {
			o.policies[p.PolicySummary.ID] = p
		}
		for _, a := range record.Attachments {
			o.attachments[a.TargetID] = append(o.attachments[a.TargetID], a.PolicyID)
		}
		o.effectivePolicies = make(map[effectivePolicyKey]EffectivePolicyRecord, len(record.EffectivePolicies))
		for _, generation := range record.EffectivePolicies {
			o.effectivePolicies[effectivePolicyKey{generation.AccountID, generation.PolicyType}] = generation
		}
		for _, t := range record.Tags {
			if o.tags[t.ResourceID] == nil {
				o.tags[t.ResourceID] = make(map[string]string)
			}
			o.tags[t.ResourceID][t.Key] = t.Value
		}
		for _, s := range record.Services {
			o.services[s.Principal] = s.Enabled
		}
		for _, d := range record.Delegations {
			if o.delegates[d.AccountID] == nil {
				o.delegates[d.AccountID] = make(map[string]float64)
			}
			o.delegates[d.AccountID][d.Principal] = d.Enabled
		}
		st.orgs[o.organization.ID] = o
	}
	return st
}

func (st *serviceState) record() PartitionRecord {
	out := PartitionRecord{AccountSequence: st.nextAccount}
	for _, id := range slices.Sorted(maps.Keys(st.handshakes)) {
		out.Handshakes = append(out.Handshakes, st.handshakes[id])
	}
	for _, id := range slices.Sorted(maps.Keys(st.knownAccounts)) {
		out.Accounts = append(out.Accounts, st.knownAccounts[id])
	}
	for _, id := range slices.Sorted(maps.Keys(st.orgs)) {
		o := st.orgs[id]
		record := OrganizationRecord{Organization: o.organization, ResourcePolicy: o.resourcePolicy, Root: o.root, RootAccess: o.rootAccess}
		for _, id := range slices.Sorted(maps.Keys(o.accounts)) {
			record.Accounts = append(record.Accounts, o.accounts[id])
		}
		for _, id := range slices.Sorted(maps.Keys(o.units)) {
			record.Units = append(record.Units, o.units[id])
		}
		for _, id := range slices.Sorted(maps.Keys(o.parents)) {
			record.Parents = append(record.Parents, ParentRecord{ChildID: id, ParentID: o.parents[id]})
		}
		for _, id := range slices.Sorted(maps.Keys(o.creations)) {
			record.Creations = append(record.Creations, o.creations[id])
		}
		for _, id := range slices.Sorted(maps.Keys(o.policies)) {
			record.Policies = append(record.Policies, o.policies[id])
		}
		for _, target := range slices.Sorted(maps.Keys(o.attachments)) {
			for _, id := range o.attachments[target] {
				record.Attachments = append(record.Attachments, PolicyAttachment{TargetID: target, PolicyID: id})
			}
		}
		keys := slices.Collect(maps.Keys(o.effectivePolicies))
		slices.SortFunc(keys, func(a, b effectivePolicyKey) int {
			if a.account != b.account {
				return strings.Compare(a.account, b.account)
			}
			return strings.Compare(a.kind, b.kind)
		})
		for _, key := range keys {
			record.EffectivePolicies = append(record.EffectivePolicies, o.effectivePolicies[key])
		}
		for _, resource := range slices.Sorted(maps.Keys(o.tags)) {
			for _, name := range slices.Sorted(maps.Keys(o.tags[resource])) {
				record.Tags = append(record.Tags, ResourceTagRecord{ResourceID: resource, Key: name, Value: o.tags[resource][name]})
			}
		}
		for _, principal := range slices.Sorted(maps.Keys(o.services)) {
			record.Services = append(record.Services, ServiceAccessRecord{Principal: principal, Enabled: o.services[principal]})
		}
		for _, account := range slices.Sorted(maps.Keys(o.delegates)) {
			for _, principal := range slices.Sorted(maps.Keys(o.delegates[account])) {
				record.Delegations = append(record.Delegations, DelegationRecord{AccountID: account, Principal: principal, Enabled: o.delegates[account][principal]})
			}
		}
		out.Organizations = append(out.Organizations, record)
	}
	return out
}
