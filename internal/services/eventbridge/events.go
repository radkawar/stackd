package eventbridge

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/eventpattern"
	"stackd/internal/services/eventbridge/inputtransform"
	"stackd/journal"
)

func (s *Service) registerEvents() {
	register(s, "PutEvents", s.PutEvents)
	register(s, "TestEventPattern", s.testPattern)
}

type eventDocument struct {
	Version    string          `json:"version"`
	ID         string          `json:"id"`
	DetailType string          `json:"detail-type"`
	Source     string          `json:"source"`
	Account    string          `json:"account"`
	Time       time.Time       `json:"time"`
	Region     string          `json:"region"`
	Resources  []string        `json:"resources"`
	Detail     json.RawMessage `json:"detail"`
	ReplayName string          `json:"replay-name,omitempty"`
}

func eventBody(event EventRecord) (string, error) {
	resources := event.Resources
	if resources == nil {
		resources = []string{}
	}
	body, err := json.Marshal(eventDocument{Version: "0", ID: event.WireID, DetailType: event.DetailType, Source: event.Source, Account: event.Account, Time: event.Time.UTC().Truncate(time.Second), Region: event.Region, Resources: resources, Detail: json.RawMessage(event.Detail), ReplayName: event.ReplayName})
	return string(body), err
}
func (s *Service) testPattern(ctx context.Context, in *api.TestEventPatternInput) (out *api.TestEventPatternOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "TestEventPattern", in, &out, &rejected, true)
	err := s.repository.View(ctx, func(tx Reader) error {
		return s.authorize(tx, "TestEventPattern", "*", nil, nil, authorization.BoundPolicy{})
	})
	if err != nil {
		return nil, wireError(err)
	}
	pattern, err := eventpattern.Compile([]byte(value(in.EventPattern)))
	if err != nil {
		if errors.Is(err, eventpattern.ErrEmptyAnythingButList) {
			return nil, failure("InternalFailure", "", 500)
		}
		return nil, failure("InvalidEventPatternException", err.Error())
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal([]byte(value(in.Event)), &envelope) != nil || envelope == nil {
		return nil, failure("ValidationException", "Parameter Event is not valid.")
	}
	for _, field := range []string{"id", "detail-type", "source", "account", "time", "region"} {
		if _, exists := envelope[field]; !exists {
			return nil, failure("ValidationException", "Parameter Event is not valid.")
		}
	}
	var stamp time.Time
	if json.Unmarshal(envelope["time"], &stamp) != nil || string(envelope["time"]) == "null" {
		return nil, failure("ValidationException", "Parameter Event is not valid. Reason: Invalid time.")
	}
	matched, err := pattern.Match([]byte(value(in.Event)))
	if err != nil {
		return nil, failure("InvalidEventPatternException", err.Error())
	}
	return &api.TestEventPatternOutput{Result: ptr(api.Boolean(matched))}, nil
}

// CheckPutEvents checks destination permissions without creating a bus or event.
// AWS admits a missing event bus when the execution role permits PutEvents.
func (s *Service) CheckPutEvents(ctx context.Context, arn string) *awswire.Error {
	key, rejected := busKey(ctx, arn)
	if rejected != nil {
		return rejected
	}
	err := s.repository.View(ctx, func(r Reader) error {
		bus, err := r.Bus(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		return s.authorize(r, "PutEvents", key.ARN(), bus.Tags, nil, bus.Policy)
	})
	return wireError(err)
}

// PutEvents authorizes and admits ordinary client and execution-role events.
func (s *Service) PutEvents(ctx context.Context, in *api.PutEventsInput) (out *api.PutEventsOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "PutEvents", in, &out, &rejected, false)
	started := s.clock.Now()
	if in.EndpointId != nil {
		return nil, unsupported("Global EventBridge endpoints are not implemented.")
	}
	size, complete := putEventsSize(in)
	if s.metrics != nil {
		defer func() {
			if rejected != nil {
				if err := s.recordRejectedPutEvents(ctx, &size); err != nil {
					out, rejected = nil, wireError(err)
				}
			}
		}()
	}
	if size >= 1<<20 {
		return nil, failure("ValidationException", "Total event entry size must be less than 1048576 bytes.")
	}
	if !complete {
		return nil, failure("ValidationException", "Source, DetailType and Detail are required for at least one entry.")
	}
	out = &api.PutEventsOutput{Entries: api.PutEventsResultEntryList{}, FailedEntryCount: ptr(api.Integer(0))}
	prepared := make([]*busEncryption, len(in.Entries))
	failures := make([]*awswire.Error, len(in.Entries))
	defer func() {
		for _, p := range prepared {
			if p != nil {
				clear(p.plain)
			}
		}
	}()
	for i, entry := range in.Entries {
		if rejected := validateEventEntry(entry); rejected != nil {
			failures[i] = rejected
			continue
		}
		key, rejected := busKey(ctx, value(entry.EventBusName))
		if rejected != nil {
			failures[i] = rejected
			continue
		}
		prepared[i], failures[i] = s.prepareBusEncryption(ctx, key, value(entry.Source), value(entry.DetailType), true, "false")
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		for i, entry := range in.Entries {
			var id string
			var err error
			if failures[i] != nil {
				err = failures[i]
			} else {
				id, err = s.admit(tx, entry, prepared[i])
			}
			if err != nil {
				var wire *awswire.Error
				if !errors.As(err, &wire) || wire.Code == "AccessDeniedException" || wire.StatusCode >= 500 && wire.Code != "NotImplementedException" {
					return err
				}
				out.Entries = append(out.Entries, api.PutEventsResultEntry{ErrorCode: str[api.ErrorCode](wire.Code), ErrorMessage: str[api.ErrorMessage](wire.Message)})
				*out.FailedEntryCount++
			} else {
				out.Entries = append(out.Entries, api.PutEventsResultEntry{EventId: str[api.EventId](id)})
			}
		}
		if err := s.stagePutEventsMetrics(tx, started, size, in, out); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PutEvents", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}
func validateEventEntry(in api.PutEventsRequestEntry) *awswire.Error {
	if in.Source == nil || in.DetailType == nil || in.Detail == nil {
		return failure("InvalidArgument", "Source, DetailType and Detail are required.")
	}
	if strings.HasPrefix(value(in.Source), "aws.") {
		return failure("NotAuthorizedForSourceException", "Not authorized for the source.")
	}
	var detail map[string]json.RawMessage
	if json.Unmarshal([]byte(value(in.Detail)), &detail) != nil || detail == nil {
		return failure("MalformedDetail", "Detail is malformed.")
	}
	return nil
}
func (s *Service) admit(tx Transaction, in api.PutEventsRequestEntry, encryption *busEncryption) (string, error) {
	ctx := tx.Context()
	k, wire := busKey(ctx, value(in.EventBusName))
	if wire != nil {
		return "", wire
	}
	m := awsctx.FromContext(ctx)
	id := identifier()
	bus, err := s.bus(tx, k)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", err
	}
	conditions := map[string][]string{"events:source": {value(in.Source)}, "events:detail-type": {value(in.DetailType)}, "events:eventBusInvocation": {"false"}}
	if auth := s.authorize(tx, "PutEvents", k.ARN(), bus.Tags, conditions, bus.Policy); auth != nil {
		return "", auth
	}
	// AWS acknowledges events addressed to a nonexistent bus, then drops them.
	if errors.Is(err, ErrNotFound) {
		return id, nil
	}
	now := s.clock.Now()
	event := EventRecord{ID: id, WireID: id, Bus: k, Source: value(in.Source), DetailType: value(in.DetailType), Detail: value(in.Detail), Time: now, Accepted: now, Account: m.AccountID, Region: k.Region, RequestID: m.RequestID, ActorARN: m.PrincipalARN}
	event.TraceHeader = eventTraceHeader(value(in.TraceHeader), in.TraceHeader != nil, m.TraceHeader, now)
	if in.Time != nil {
		event.Time = time.Time(*in.Time).UTC()
	}
	for _, resource := range in.Resources {
		event.Resources = append(event.Resources, string(resource))
	}
	return id, commitEvent(tx, event, s.events, s.metrics, eventSelection{Encryption: encryption})
}

type eventSelection struct {
	ManagementRead bool
	Scheduled      *RuleKey
	FilterARNs     []string
	Encryption     *busEncryption
}

// commitEvent owns matching, input projection and retained target work for both
// client PutEvents and trusted service producers. Authorization stays with
// the producing command; first-party events do not impersonate a customer call.
// A scheduled source rule is selected once independently of its event pattern;
// every other rule still observes the same bus-wide event.
func commitEvent(tx Transaction, event EventRecord, events Events, metrics MetricPublisher, selection eventSelection) error {
	k, id, now := event.Bus, event.ID, event.Accepted
	body, err := eventBody(event)
	if err != nil {
		return err
	}
	rules, err := tx.Rules(k)
	if err != nil {
		return err
	}
	retained, err := selection.Encryption.retain(tx, event, body)
	if err != nil {
		return err
	}
	if err := tx.PutEvent(retained); err != nil {
		return err
	}
	if len(retained.ConfigurationDataKey) != 0 {
		if err := retainEncryptedSelection(tx, retained, rules, selection); err != nil {
			return err
		}
		return appendAcceptedEvent(tx, event, events)
	}
	var samples []MetricSample
	var matches int
	var invocations int64
	for _, rule := range rules {
		if rule.State == "DISABLED" || selection.ManagementRead && rule.State != "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" {
			continue
		}
		ruleARN := rule.Key.ARN()
		if len(selection.FilterARNs) != 0 && !slices.Contains(selection.FilterARNs, ruleARN) {
			continue
		}
		if selection.Scheduled == nil || rule.Key != *selection.Scheduled {
			if rule.Pattern == "" {
				continue
			}
			pattern, err := eventpattern.Compile([]byte(rule.Pattern))
			if err != nil {
				return err
			}
			matched, err := pattern.Match([]byte(body))
			if err != nil {
				return err
			}
			if !matched {
				continue
			}
		}
		targets, err := tx.Targets(rule.Key)
		if err != nil {
			return err
		}
		if metrics != nil {
			matches++
			invocations += int64(len(targets))
			samples = append(samples, ruleMetric(rule.Key, "MatchedEvents", 1), ruleMetric(rule.Key, "TriggeredRules", 1))
		}
		for _, target := range targets {
			delivery := DeliveryRecord{ID: identifier(), EventID: id, RuleARN: ruleARN, ArchiveID: rule.ArchiveID, TargetID: target.ID, TargetARN: target.ARN, RoleARN: target.RoleARN, MessageGroupID: target.MessageGroupID, DeadLetterARN: target.DeadLetterARN, MaxRetries: target.MaxRetries, MaxAgeSeconds: target.MaxAgeSeconds, Due: now, Version: 1, State: "pending"}
			delivery.EcsParameters = cloneECSParameters(target.EcsParameters)
			delivery.KinesisParameters = cloneKinesisParameters(target.KinesisParameters)
			delivery.HttpParameters = cloneHTTPParameters(target.HttpParameters)
			if rule.ArchiveID == "" && (target.Input.Input != nil || target.Input.InputPath != nil || target.Input.Transformer != nil) {
				projection, err := inputtransform.Compile(target.Input)
				if err != nil {
					return err
				}
				body, err := projection.Apply([]byte(body), inputtransform.Context{RuleARN: delivery.RuleARN, RuleName: rule.Key.Name, IngestionTime: now})
				if err != nil && !errors.Is(err, inputtransform.ErrInvalidJSON) {
					return err
				}
				delivery.Input, delivery.HasInput = string(body), true
				if err != nil {
					delivery.LastErrorCode, delivery.LastErrorMessage = "INVALID_JSON", "Invalid input for target."
					delivery.State = "failed"
					if delivery.DeadLetterARN != "" {
						delivery.State = "dead-letter"
					}
				}
			}
			if err := tx.PutDelivery(delivery); err != nil {
				return err
			}
			if metrics != nil && delivery.LastErrorCode != "" {
				samples = appendFailedRuleMetrics(samples, rule.Key)
			}
		}
	}
	if metrics != nil {
		if err := stageEventMetrics(tx, event, samples, matches, invocations); err != nil {
			return err
		}
	}
	return appendAcceptedEvent(tx, event, events)
}

func appendAcceptedEvent(tx Transaction, event EventRecord, events Events) error {
	if events == nil {
		return nil
	}
	k := event.Bus
	return events.AppendEventBridgeAccepted(tx.Context(), apievents.WithOrigin(tx.Context(), journal.Envelope{At: event.Accepted, Partition: k.Partition, AccountID: k.Account, Region: k.Region}), journal.EventBridgeAccepted{EventID: event.ID, WireEventID: event.WireID, EventBusARN: k.ARN()})
}
