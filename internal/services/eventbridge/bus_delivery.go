package eventbridge

import (
	"context"
	"slices"
	"strings"
	"time"

	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/eventpattern"
)

func retainEncryptedSelection(tx Transaction, event EventRecord, rules []RuleRecord, selection eventSelection) error {
	for _, rule := range rules {
		if rule.State == "DISABLED" || selection.ManagementRead && rule.State != "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" {
			continue
		}
		if len(selection.FilterARNs) != 0 && !slices.Contains(selection.FilterARNs, rule.Key.ARN()) {
			continue
		}
		targets, err := tx.Targets(rule.Key)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			targets = []TargetRecord{{Rule: rule.Key}}
		}
		for _, target := range targets {
			delivery := DeliveryRecord{ID: identifier(), EventID: event.ID, RuleARN: rule.Key.ARN(), ArchiveID: rule.ArchiveID, TargetID: target.ID, TargetARN: target.ARN, RoleARN: target.RoleARN, DeadLetterARN: target.DeadLetterARN, MaxRetries: target.MaxRetries, MaxAgeSeconds: target.MaxAgeSeconds, Due: event.Accepted, Version: 1, State: "awaiting-bus", RulePattern: rule.EncryptedPattern, TargetConfiguration: target.EncryptedConfiguration, MatchOnly: target.ID == "", RuleMatched: selection.Scheduled != nil && *selection.Scheduled == rule.Key}
			if err := tx.PutDelivery(delivery); err != nil {
				return err
			}
		}
	}
	return tx.PutDelivery(DeliveryRecord{ID: identifier(), EventID: event.ID, RuleARN: event.Bus.ARN(), BusProcessing: true, DeadLetterARN: event.BusDeadLetterARN, MaxRetries: 185, MaxAgeSeconds: 86400, Due: event.Accepted, Version: 1, State: "pending"})
}

// Configuration snapshots and both wrapped keys belong to the accepted event,
// not the bus's current settings. Matching and KMS run outside transactions.
func (s *Service) processBusEvent(ctx context.Context, selected DeliveryRecord, event EventRecord, now time.Time) error {
	if selected.State == "dead-letter" {
		body, err := encryptedBusDeadLetter(event)
		if err != nil {
			return err
		}
		request := DeliveryRequest{Event: body, Delivery: selected, Attributes: map[string]string{"ERROR_CODE": selected.LastErrorCode, "ERROR_MESSAGE": selected.LastErrorMessage}}
		request.Delivery.TargetARN = selected.DeadLetterARN
		var rejected *awswire.Error
		if s.delivery == nil {
			rejected = failure("InternalException", "No target delivery adapter is configured.", 500)
		} else {
			rejected = s.delivery.Send(ctx, request)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return s.finishDelivery(ctx, selected, event, rejected, false, now)
	}
	var children []DeliveryRecord
	if err := s.repository.View(ctx, func(r Reader) error { var err error; children, err = r.EventDeliveries(event.ID); return err }); err != nil {
		return err
	}
	opened, _, rejected := s.openBusEvent(ctx, event, selected)
	matches := map[string]bool{}
	if rejected == nil {
		aead, denied := s.configurationCipher(ctx, BusRecord{Key: event.Bus, ConfigurationDataKey: event.ConfigurationDataKey}, false)
		rejected = denied
		if rejected == nil {
			body, err := eventBody(opened)
			if err != nil {
				return err
			}
			for _, child := range children {
				if child.BusProcessing {
					continue
				}
				if _, found := matches[child.RuleARN]; found {
					continue
				}
				if child.RuleMatched {
					matches[child.RuleARN] = true
					continue
				}
				matches[child.RuleARN] = false
				if len(child.RulePattern) == 0 {
					continue
				}
				pattern, denied := openEnvelope(aead, child.RulePattern)
				if denied != nil {
					rejected = denied
					break
				}
				compiled, err := eventpattern.Compile(pattern)
				if err != nil {
					return err
				}
				matched, err := compiled.Match([]byte(body))
				if err != nil {
					return err
				}
				matches[child.RuleARN] = matched
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if rejected != nil && retryable(rejected) && selected.Attempts < selected.MaxRetries && now.Before(event.Accepted.Add(time.Duration(selected.MaxAgeSeconds)*time.Second)) {
		return s.finishDelivery(ctx, selected, event, rejected, false, now)
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Delivery(selected.ID)
		if err != nil {
			return err
		}
		if current.Version != selected.Version {
			return nil
		}
		current.Version++
		current.Attempts++
		current.State = "delivered"
		if rejected != nil {
			current.State = "failed"
			current.LastErrorCode, current.LastErrorMessage = "RULE_DECRYPTION_FAILURE", "Unable to decrypt rule using the Kms key."
			if current.DeadLetterARN != "" {
				current.State, current.Due = "dead-letter", now
			}
		}
		var invocations int64
		for _, child := range children {
			if child.State != "awaiting-bus" {
				continue
			}
			child.Version++
			child.Due = now
			child.State = "unmatched"
			if rejected != nil {
				child.State = "failed"
			} else if matches[child.RuleARN] {
				child.State = "pending"
				if child.MatchOnly {
					child.State = "delivered"
				} else {
					invocations++
				}
			}
			if err := tx.PutDelivery(child); err != nil {
				return err
			}
		}
		if s.metrics != nil && rejected == nil {
			var samples []MetricSample
			count := 0
			for arn, matched := range matches {
				if !matched {
					continue
				}
				count++
				rule := RuleKey{Bus: event.Bus, Name: arn[strings.LastIndexByte(arn, '/')+1:]}
				samples = append(samples, ruleMetric(rule, "MatchedEvents", 1), ruleMetric(rule, "TriggeredRules", 1))
			}
			if err := stageEventMetrics(tx, event, samples, count, invocations); err != nil {
				return err
			}
		}
		return tx.PutDelivery(current)
	})
}
