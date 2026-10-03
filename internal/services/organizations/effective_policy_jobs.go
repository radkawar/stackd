package organizations

import (
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/journal"
)

// AWS propagation varies. This service-time interval preserves its observed
// prior-view/latest-view transition without imposing wall-clock sleeps on tests.
const effectivePolicyDelay = time.Second

// scheduleEffectivePolicies coalesces affected descendants into one pending
// publication per account/type. Disabling a type removes attachments but retains
// the cached view: reads are gated by enablement while regeneration proceeds.
// Empty kind selects all enabled management types, as needed by membership changes.
func (s *operationState) scheduleEffectivePolicies(o *orgState, targets []string, kind string, origin awsctx.Metadata) {
	if len(targets) == 0 || kind == "SERVICE_CONTROL_POLICY" || kind == "RESOURCE_CONTROL_POLICY" {
		return
	}
	kinds := []string{kind}
	if kind == "" {
		kinds = nil
		for _, t := range o.root.PolicyTypes {
			if t.Status == "ENABLED" && t.Type != "SERVICE_CONTROL_POLICY" && t.Type != "RESOURCE_CONTROL_POLICY" {
				kinds = append(kinds, t.Type)
			}
		}
	}
	for _, account := range slices.Sorted(maps.Keys(o.accounts)) {
		for id := account; id != ""; id = o.parents[id] {
			if !slices.Contains(targets, id) {
				continue
			}
			for _, kind := range kinds {
				if o.effectivePolicies == nil {
					o.effectivePolicies = make(map[effectivePolicyKey]EffectivePolicyRecord)
				}
				key := effectivePolicyKey{account, kind}
				p := o.effectivePolicies[key]
				p.AccountID, p.PolicyType = account, kind
				p.Due = new(s.instant.Add(effectivePolicyDelay))
				p.RequestID, p.RequestRegion, p.ActorARN = origin.RequestID, origin.Region, origin.PrincipalARN
				o.effectivePolicies[key] = p
				s.recordEffectivePolicy(o, p, journal.EffectivePolicyScheduled, origin)
			}
			break
		}
	}
}

// Empty account removes every view when deleting the organization.
func (s *operationState) removeEffectivePolicies(o *orgState, account string, origin awsctx.Metadata) {
	accounts := []string{account}
	if account == "" {
		accounts = slices.Sorted(maps.Keys(o.accounts))
	}
	for _, account := range accounts {
		var kinds []string
		for key := range o.effectivePolicies {
			if key.account == account {
				kinds = append(kinds, key.kind)
			}
		}
		slices.Sort(kinds)
		for _, kind := range kinds {
			key := effectivePolicyKey{account, kind}
			s.recordEffectivePolicy(o, o.effectivePolicies[key], journal.EffectivePolicyRemoved, origin)
			delete(o.effectivePolicies, key)
		}
	}
}

type effectivePolicyJobs struct{ service *Service }

func (source effectivePolicyJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	partitions, err := source.service.storage.Partitions(ctx)
	if err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	for _, partition := range partitions {
		record, _, err := source.service.storage.Load(ctx, partition)
		if err != nil {
			return scheduler.Job{}, false, err
		}
		for _, org := range record.Organizations {
			for _, p := range org.EffectivePolicies {
				if p.Due == nil {
					continue
				}
				candidate := scheduler.Job{Key: partition + "/" + org.Organization.ID + "/" + p.AccountID + "/" + p.PolicyType, Due: *p.Due}
				if !found || scheduler.Compare(candidate, next) < 0 {
					next, found = candidate, true
				}
			}
		}
	}
	return next, found, nil
}

func (source effectivePolicyJobs) Run(ctx context.Context, selected scheduler.Job) error {
	partition, rest, _ := strings.Cut(selected.Key, "/")
	orgID, rest, _ := strings.Cut(rest, "/")
	account, kind, _ := strings.Cut(rest, "/")
	s := source.service
	record, revision, err := s.storage.Load(ctx, partition)
	if err != nil {
		return err
	}
	worker := &operationState{serviceState: decodeState(record, partition, ""), instant: s.clock.Now()}
	o := worker.orgs[orgID]
	if o == nil {
		return nil
	}
	key := effectivePolicyKey{account, kind}
	p := o.effectivePolicies[key]
	if p.Due == nil || !p.Due.Equal(selected.Due) || p.Due.After(worker.instant) {
		return nil
	}
	content, diagnostics, err := o.effectivePolicyContent(account, kind, worker.instant)
	if err != nil {
		return err
	}
	p.ValidationErrors = diagnostics
	if len(diagnostics) == 0 {
		p.Content = content
	} else if p.Content == "" {
		p.Content = "{}"
	}
	p.ValidationPath = ""
	if len(p.ValidationErrors) > 0 {
		p.ValidationPath = o.entityPath(account)
	}
	p.UpdatedAt = worker.instant
	worker.recordEffectivePolicy(o, p, journal.EffectivePolicyPublished, awsctx.Metadata{RequestID: p.RequestID, Region: p.RequestRegion, PrincipalARN: p.ActorARN})
	p.Due, p.RequestID, p.RequestRegion, p.ActorARN = nil, "", "", ""
	o.effectivePolicies[key] = p
	_, err = s.commit(ctx, partition, revision, worker)
	return err
}
