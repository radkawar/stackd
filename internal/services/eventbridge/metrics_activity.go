package eventbridge

import (
	"strings"
	"time"
)

func ruleMetric(rule RuleKey, name string, value float64) MetricSample {
	sample := MetricSample{Name: name, RuleName: rule.Name, Value: value, SampleCount: 1}
	if rule.Bus.Name != "default" {
		sample.EventBusName = rule.Bus.Name
	}
	return sample
}

func appendRuleMetric(samples []MetricSample, rule RuleKey, name string, value float64) []MetricSample {
	return append(samples, MetricSample{Name: name, Value: value, SampleCount: 1}, ruleMetric(rule, name, value))
}

func stageEventMetrics(tx Transaction, event EventRecord, samples []MetricSample, matches int, invocations int64) error {
	if matches == 0 {
		return nil
	}
	samples = append(samples,
		MetricSample{Name: "MatchedEvents", Value: 1, SampleCount: 1},
		MetricSample{Name: "TriggeredRules", Value: float64(matches), SampleCount: 1})
	if event.Source != "" {
		samples = append(samples, MetricSample{Name: "MatchedEvents", Source: event.Source, Value: 1, SampleCount: 1})
	}
	if invocations != 0 {
		samples = append(samples, MetricSample{Name: "InvocationsCreated", Value: 1, SampleCount: invocations})
	}
	return tx.AddMetricSamples(MetricPublicationKey{Scope: event.Bus.Scope, Minute: event.Accepted.UTC().Truncate(time.Minute)}, samples)
}

// stageDeliveryMetrics records only the committed transition. Stale execution
// results cannot double-count a delivery whose version another job advanced.
func (s *Service) stageDeliveryMetrics(tx Transaction, before, after DeliveryRecord, event EventRecord, started time.Time, attempted bool) error {
	if s.metrics == nil || before.BusProcessing {
		return nil
	}
	completed := s.clock.Now()
	rule := RuleKey{Bus: event.Bus, Name: before.RuleARN[strings.LastIndexByte(before.RuleARN, '/')+1:]}
	_, target, _ := strings.Cut(before.TargetARN, ":")
	_, target, _ = strings.Cut(target, ":")
	targetService, _, _ := strings.Cut(target, ":")
	busTarget := targetService == "events" && strings.Contains(before.TargetARN, ":event-bus/") && before.ArchiveID == ""
	deadLetter := before.State == "dead-letter"
	var samples []MetricSample
	// Native bus forwarding publishes legacy invocation counters, not modern
	// attempts. Its SQS DLQ is the measured attempt. Other targets do not count
	// their DLQ send as another target invocation.
	if attempted && ((!busTarget && !deadLetter) || (busTarget && deadLetter)) {
		samples = appendRuleMetric(samples, rule, "InvocationAttempts", 1)
		if before.Attempts != 0 && !deadLetter {
			samples = appendRuleMetric(samples, rule, "RetryInvocationAttempts", 1)
		} else {
			samples = appendRuleMetric(samples, rule, "IngestionToInvocationStartLatency", float64(started.Sub(event.Accepted))/float64(time.Millisecond))
			samples = appendRuleMetric(samples, rule, "IngestionToInvocationCompleteLatency", float64(completed.Sub(event.Accepted))/float64(time.Millisecond))
		}
		if after.State == "delivered" || after.State == "dead-lettered" {
			samples = appendRuleMetric(samples, rule, "SuccessfulInvocationAttempts", 1)
			samples = appendRuleMetric(samples, rule, "IngestionToInvocationSuccessLatency", float64(completed.Sub(event.Accepted))/float64(time.Millisecond))
		}
	}
	if deadLetter {
		name := "InvocationsSentToDlq"
		if after.State == "failed-dead-letter" {
			name = "InvocationsFailedToBeSentToDlq"
		}
		samples = appendRuleMetric(samples, rule, name, 1)
	} else {
		switch after.State {
		case "delivered":
			samples = appendRuleMetric(samples, rule, "Invocations", 1)
		case "failed", "dead-letter":
			samples = appendFailedRuleMetrics(samples, rule)
		}
	}
	return tx.AddMetricSamples(MetricPublicationKey{Scope: event.Bus.Scope, Minute: completed.UTC().Truncate(time.Minute)}, samples)
}

func appendFailedRuleMetrics(samples []MetricSample, rule RuleKey) []MetricSample {
	samples = appendRuleMetric(samples, rule, "Invocations", 1)
	return appendRuleMetric(samples, rule, "FailedInvocations", 1)
}
