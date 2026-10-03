package xray

import (
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/xray"
)

const (
	samplingInterval = 10 * time.Second
	samplingLease    = 5 * time.Minute
)

type samplingAllocation struct {
	rule       SamplingRuleRecord
	clients    map[string]SamplingClientRecord
	statistics map[SamplingStatisticKey]SamplingStatisticRecord
}

func loadSamplingAllocation(tx Reader, rule SamplingRuleRecord, now time.Time) (*samplingAllocation, error) {
	clients, err := tx.SamplingClients(rule.Key)
	if err != nil {
		return nil, err
	}
	statistics, err := tx.SamplingStatistics(rule.Key)
	if err != nil {
		return nil, err
	}
	allocation := &samplingAllocation{rule: rule, clients: make(map[string]SamplingClientRecord, len(clients)), statistics: make(map[SamplingStatisticKey]SamplingStatisticRecord, len(statistics))}
	for _, client := range clients {
		if client.LastSeen.After(now.Add(-samplingLease)) || client.QuotaExpires.After(now) {
			allocation.clients[client.Key.ID] = client
		}
	}
	for _, statistic := range statistics {
		if statistic.Received.After(now.Add(-samplingLease)) {
			allocation.statistics[statistic.Key] = statistic
		}
	}
	return allocation, nil
}

func (s *Service) getSamplingTargets(tx Transaction, in *api.GetSamplingTargetsRequest) (*api.GetSamplingTargetsResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:GetSamplingTargets", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	modified, err := tx.SamplingModified(scope)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	out := &api.GetSamplingTargetsResult{LastRuleModification: new(modified), SamplingTargetDocuments: api.SamplingTargetDocumentList{}, UnprocessedStatistics: api.UnprocessedStatisticsList{}}
	allocations := make(map[string]*samplingAllocation)
	// Admit all reports before allocation, so a batch's order cannot give its first
	// client a reservoir that belongs to other clients in the same batch.
	for _, document := range in.SamplingStatisticsDocuments {
		name := value(document.RuleName)
		allocation, found := allocations[name]
		if !found {
			rule, err := samplingRule(tx, SamplingRuleKey{Scope: scope, Name: name})
			if errors.Is(err, ErrNotFound) {
				allocations[name] = nil
			} else if err != nil {
				return nil, err
			} else {
				allocation, err = loadSamplingAllocation(tx, rule, now)
				if err != nil {
					return nil, err
				}
				allocations[name] = allocation
			}
		}
		if allocation == nil {
			out.UnprocessedStatistics = append(out.UnprocessedStatistics, unknownSamplingRule(name))
			continue
		}
		id := value(document.ClientID)
		client, found := allocation.clients[id]
		if !found {
			client = SamplingClientRecord{Key: SamplingClientKey{Rule: allocation.rule.Key, ID: id}, FirstSeen: now}
		}
		client.LastSeen = now
		allocation.clients[id] = client
		// Native accepts stale/future statistics without rejecting the document. They
		// cannot contaminate the current reporting window or extend stored history.
		timestamp := document.Timestamp.UTC()
		if timestamp.After(now) || timestamp.Before(now.Add(-samplingLease)) {
			continue
		}
		key := SamplingStatisticKey{Rule: allocation.rule.Key, ClientID: id, Window: timestamp.Truncate(samplingInterval)}
		previous, exists := allocation.statistics[key]
		if exists && !timestamp.After(previous.Timestamp) {
			continue
		}
		statistic := SamplingStatisticRecord{Key: key, Timestamp: timestamp, Received: now}
		if document.RequestCount != nil {
			statistic.RequestCount = int64(*document.RequestCount)
		}
		if document.SampledCount != nil {
			statistic.SampledCount = int64(*document.SampledCount)
		}
		if document.BorrowCount != nil {
			statistic.BorrowCount = int64(*document.BorrowCount)
		}
		allocation.statistics[key] = statistic
		if err := tx.PutSamplingStatistic(statistic); err != nil {
			return nil, err
		}
	}
	// Stable client order also makes scarce integer remainder allocation repeatable.
	names := make([]string, 0, len(allocations))
	for name, allocation := range allocations {
		if allocation != nil {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	targets := make(map[SamplingClientKey]api.SamplingTargetDocument)
	for _, name := range names {
		allocation := allocations[name]
		reporting := make(map[string]bool)
		for _, document := range in.SamplingStatisticsDocuments {
			if value(document.RuleName) == name {
				reporting[value(document.ClientID)] = true
			}
		}
		quotas := allocation.fairQuotas(now)
		ids := make([]string, 0, len(reporting))
		for id := range reporting {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		// Returning a replacement explicitly relinquishes the reporting client's old
		// lease. Non-reporting clients retain their full lease until expiry.
		reserved := int64(0)
		for id, client := range allocation.clients {
			if !reporting[id] && client.QuotaExpires.After(now) {
				reserved += int64(client.Quota)
			}
		}
		remaining := max(int64(0), int64(allocation.rule.ReservoirSize)-reserved)
		for _, id := range ids {
			client := allocation.clients[id]
			target := api.SamplingTargetDocument{RuleName: new(api.String(name)), FixedRate: new(api.Double(allocation.rule.FixedRate))}
			// Initial borrowing lasts until one reporting window has closed. This is a
			// local deterministic convergence policy, not an asserted AWS cache delay.
			if client.FirstSeen.Truncate(samplingInterval).Before(now.Truncate(samplingInterval)) {
				client.Quota = int32(min(int64(quotas[id]), remaining))
				remaining -= int64(client.Quota)
				client.QuotaExpires = now.Add(samplingLease).Truncate(time.Second)
				target.Interval = new(api.NullableInteger(10))
				target.ReservoirQuota = new(api.NullableInteger(client.Quota))
				target.ReservoirQuotaTTL = new(client.QuotaExpires)
			}
			if err := tx.PutSamplingClient(client); err != nil {
				return nil, err
			}
			targets[client.Key] = target
		}
	}
	for _, document := range in.SamplingStatisticsDocuments {
		key := SamplingClientKey{Rule: SamplingRuleKey{Scope: scope, Name: value(document.RuleName)}, ID: value(document.ClientID)}
		if target, ok := targets[key]; ok {
			out.SamplingTargetDocuments = append(out.SamplingTargetDocuments, target)
		}
	}
	if err := s.samplingBoostTargets(tx, in, out, now); err != nil {
		return nil, err
	}
	if err := s.recordSamplingRates(tx, out.SamplingTargetDocuments, allocations); err != nil {
		return nil, err
	}
	return out, nil
}

// fairQuotas divides the global reservoir evenly, redistributing unused capacity
// from low-traffic clients. Existing leases are reconciled separately: fair-share
// changes never spend another client's outstanding quota before replacement.
func (a *samplingAllocation) fairQuotas(now time.Time) map[string]int32 {
	demand := make(map[string]int64, len(a.clients))
	latest := make(map[string]time.Time, len(a.clients))
	for _, statistic := range a.statistics {
		id := statistic.Key.ClientID
		if statistic.Timestamp.After(now) || statistic.Timestamp.Before(now.Add(-samplingLease)) || !statistic.Timestamp.After(latest[id]) {
			continue
		}
		latest[id] = statistic.Timestamp
		demand[id] = (statistic.RequestCount + 9) / 10
	}
	ids := make([]string, 0, len(a.clients))
	for id, client := range a.clients {
		if client.LastSeen.After(now.Add(-samplingLease)) && demand[id] > 0 {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	quotas := make(map[string]int32, len(ids))
	remaining := int64(a.rule.ReservoirSize)
	// Each pass exhausts at least one demand or all remaining capacity; runtime is
	// bounded by client count rather than reservoir size.
	for len(ids) > 0 && remaining > 0 {
		share := max(int64(1), remaining/int64(len(ids)))
		active := ids[:0]
		for _, id := range ids {
			grant := min(share, demand[id]-int64(quotas[id]), remaining)
			quotas[id] += int32(grant)
			remaining -= grant
			if int64(quotas[id]) < demand[id] {
				active = append(active, id)
			}
		}
		ids = active
	}
	return quotas
}

func unknownSamplingRule(name string) api.UnprocessedStatistics {
	return api.UnprocessedStatistics{RuleName: new(api.String(name)), ErrorCode: new(api.String("400")), Message: new(api.String("Unknown rule"))}
}

func (s *Service) getSamplingStatisticSummaries(tx Transaction, _ *api.GetSamplingStatisticSummariesRequest) (*api.GetSamplingStatisticSummariesResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:GetSamplingStatisticSummaries", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	rows, err := tx.SamplingRules(scope)
	if err != nil {
		return nil, err
	}
	foundDefault := false
	for _, row := range rows {
		foundDefault = foundDefault || row.Key.Name == "Default"
	}
	if !foundDefault {
		clients, err := tx.SamplingClients(SamplingRuleKey{Scope: scope, Name: "Default"})
		if err != nil {
			return nil, err
		}
		if len(clients) != 0 {
			rows = append(rows, defaultSamplingRule(scope))
		}
	}
	slices.SortFunc(rows, func(a, b SamplingRuleRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
	window := s.clock.Now().UTC().Truncate(samplingInterval).Add(-samplingInterval)
	out := &api.GetSamplingStatisticSummariesResult{SamplingStatisticSummaries: api.SamplingStatisticSummaryList{}}
	for _, row := range rows {
		statistics, err := tx.SamplingStatistics(row.Key)
		if err != nil {
			return nil, err
		}
		var requests, sampled, borrowed int64
		for _, statistic := range statistics {
			if statistic.Key.Window.Equal(window) {
				requests += statistic.RequestCount
				sampled += statistic.SampledCount
				borrowed += statistic.BorrowCount
			}
		}
		out.SamplingStatisticSummaries = append(out.SamplingStatisticSummaries, api.SamplingStatisticSummary{RuleName: new(api.String(row.Key.Name)), Timestamp: new(window), RequestCount: new(api.Integer(requests)), SampledCount: new(api.Integer(sampled)), BorrowCount: new(api.Integer(borrowed))})
	}
	return out, nil
}
