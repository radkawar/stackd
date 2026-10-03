package xray

import (
	"errors"
	"slices"
	"time"

	api "stackd/internal/awsapi/xray"
)

// samplingBoostTargets consumes service-level anomaly reports separately from
// SDK client reservoirs: downstream services can trigger a rule's boost but do
// not acquire a reservoir lease by reporting anomalies.
func (s *Service) samplingBoostTargets(tx Transaction, in *api.GetSamplingTargetsRequest, out *api.GetSamplingTargetsResult, now time.Time) error {
	scope := scopeFor(tx.Context())
	rules := make(map[string]SamplingRuleRecord)
	if in.SamplingBoostStatisticsDocuments != nil {
		out.UnprocessedBoostStatistics = api.UnprocessedStatisticsList{}
	}
	for _, document := range in.SamplingBoostStatisticsDocuments {
		name := value(document.RuleName)
		rule, err := samplingRule(tx, SamplingRuleKey{Scope: scope, Name: name})
		if errors.Is(err, ErrNotFound) {
			out.UnprocessedBoostStatistics = append(out.UnprocessedBoostStatistics, unknownSamplingRule(name))
			continue
		}
		if err != nil {
			return err
		}
		rules[name] = rule
		timestamp := document.Timestamp.UTC()
		if timestamp.After(now) || timestamp.Before(now.Add(-samplingLease)) {
			continue
		}
		key := SamplingBoostStatisticKey{Rule: rule.Key, ServiceName: value(document.ServiceName), Window: timestamp.Truncate(samplingInterval)}
		statistics, err := tx.SamplingBoostStatistics(rule.Key)
		if err != nil {
			return err
		}
		duplicate := false
		for _, statistic := range statistics {
			if statistic.Key == key && !timestamp.After(statistic.Timestamp) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		statistic := SamplingBoostStatisticRecord{Key: key, Timestamp: timestamp, Received: now, TotalCount: int64(*document.TotalCount), AnomalyCount: int64(*document.AnomalyCount), SampledAnomalyCount: int64(*document.SampledAnomalyCount)}
		if err := tx.PutSamplingBoostStatistic(statistic); err != nil {
			return err
		}
	}
	for _, target := range out.SamplingTargetDocuments {
		name := value(target.RuleName)
		if _, found := rules[name]; found {
			continue
		}
		rule, err := samplingRule(tx, SamplingRuleKey{Scope: scope, Name: name})
		if err != nil {
			return err
		}
		rules[name] = rule
	}
	names := make([]string, 0, len(rules))
	for name := range rules {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		rule := rules[name]
		if rule.RateBoost == nil || float64(*rule.RateBoost.MaxRate) <= rule.FixedRate {
			continue
		}
		boost, err := tx.SamplingBoost(rule.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		exists := err == nil
		if !exists || !boost.Expires.After(now) {
			// A cooldown is measured from activation, not from every polling request.
			// Keep the expired state row so restart cannot retrigger the same cooldown.
			cooldown := time.Duration(*rule.RateBoost.CooldownWindowMinutes) * time.Minute
			if exists && now.Before(boost.Triggered.Add(cooldown)) {
				continue
			}
			statistics, err := tx.SamplingBoostStatistics(rule.Key)
			if err != nil {
				return err
			}
			rate := rule.FixedRate
			window := now.Truncate(samplingInterval).Add(-samplingInterval)
			for _, statistic := range statistics {
				if !statistic.Key.Window.Equal(window) || exists && !statistic.Timestamp.After(boost.Triggered) || statistic.TotalCount <= 0 {
					continue
				}
				// Use the largest missing-anomaly fraction reported by any service; adding
				// services would count the same request at each downstream hop. Inconsistent
				// native-accepted counters are bounded for allocation, not rejected.
				missing := max(int64(0), min(statistic.AnomalyCount, statistic.TotalCount)-statistic.SampledAnomalyCount)
				rate = max(rate, float64(missing)/float64(statistic.TotalCount))
			}
			rate = min(rate, float64(*rule.RateBoost.MaxRate))
			if rate <= rule.FixedRate {
				continue
			}
			// This deterministic policy follows the documented maximum one-minute boost
			// and configured cooldown. AWS's adaptive estimator is not reverse-engineered
			// from the native capture's stochastic rates or rolling TTLs.
			boost = SamplingBoostRecord{Key: rule.Key, Rate: rate, Triggered: now, Expires: now.Add(time.Minute)}
			if err := tx.PutSamplingBoost(boost); err != nil {
				return err
			}
		}
		rate := min(boost.Rate, float64(*rule.RateBoost.MaxRate))
		if rate <= rule.FixedRate {
			continue
		}
		for i := range out.SamplingTargetDocuments {
			target := &out.SamplingTargetDocuments[i]
			if value(target.RuleName) == name {
				target.SamplingBoost = &api.SamplingBoost{BoostRate: new(api.Double(rate)), BoostRateTTL: new(boost.Expires)}
			}
		}
	}
	return nil
}
