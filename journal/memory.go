package journal

import (
	"context"
	"maps"
	"slices"
	"strconv"

	"stackd/storage/memory"
)

// NewMemory joins domain; nil constructs an independent domain. Only append
// mutates this store. Cloning its slice header preserves the immutable committed
// prefix; writes beyond that prefix remain invisible if a transaction rolls back.
func NewMemory(domain *memory.Domain) Storage {
	if domain == nil {
		domain = memory.NewDomain()
	}
	return &memoryJournal{
		store:      memory.New(domain, []Event(nil), func(events []Event) []Event { return events }),
		kubernetes: memory.New(domain, map[kubernetesAuditKey]struct{}{}, maps.Clone[map[kubernetesAuditKey]struct{}]),
	}
}

type memoryJournal struct {
	store      *memory.Store[[]Event]
	kubernetes *memory.Store[map[kubernetesAuditKey]struct{}]
}

func (j *memoryJournal) AppendSessionIssued(ctx context.Context, envelope Envelope, session SessionIssued) error {
	return j.append(ctx, Event{Envelope: envelope, SessionIssued: session})
}

func (j *memoryJournal) AppendAccessKeyChanged(ctx context.Context, envelope Envelope, change AccessKeyChanged) error {
	return j.append(ctx, Event{Envelope: envelope, AccessKeyChanged: change})
}

func (j *memoryJournal) AppendAccountCreationChanged(ctx context.Context, envelope Envelope, change AccountCreationChanged) error {
	return j.append(ctx, Event{Envelope: envelope, AccountCreationChanged: change})
}

func (j *memoryJournal) append(ctx context.Context, event Event) error {
	return j.store.Update(ctx, func(events *[]Event, _ *memory.Transaction) error {
		event.Sequence = int64(len(*events)) + 1
		*events = append(*events, event)
		return nil
	})
}

func (j *memoryJournal) Read(ctx context.Context, after int64, limit int) ([]Event, error) {
	if err := ValidateQuery(after, limit); err != nil {
		return nil, err
	}
	var result []Event
	err := j.store.View(ctx, func(events *[]Event, _ *memory.Transaction) error {
		if after >= int64(len(*events)) {
			result = []Event{}
			return nil
		}
		remaining := (*events)[after:]
		result = slices.Clone(remaining[:min(limit, len(remaining))])
		for i := range result {
			result[i] = cloneEvent(result[i])
		}
		return nil
	})
	return result, err
}

func (j *memoryJournal) AppendAPICallCompleted(ctx context.Context, envelope Envelope, call APICallCompleted) error {
	return j.append(ctx, cloneEvent(Event{Envelope: envelope, APICallCompleted: &call}))
}

// ReadAPICalls scans once for an entire delivery batch, not once per record.
func (j *memoryJournal) ReadAPICalls(ctx context.Context, eventIDs []string) ([]Event, error) {
	wanted := make(map[string]bool, len(eventIDs))
	for _, id := range eventIDs {
		wanted[id] = true
	}
	result := []Event{}
	err := j.store.View(ctx, func(events *[]Event, _ *memory.Transaction) error {
		for _, event := range *events {
			if event.APICallCompleted != nil && wanted[event.APICallCompleted.EventID] {
				result = append(result, cloneEvent(event))
			}
		}
		return nil
	})
	return result, err
}

func (j *memoryJournal) AppendEventBridgeAccepted(ctx context.Context, envelope Envelope, event EventBridgeAccepted) error {
	return j.append(ctx, Event{Envelope: envelope, EventBridgeAccepted: event})
}

func (j *memoryJournal) AppendLambdaInvocationAccepted(ctx context.Context, envelope Envelope, event LambdaInvocationAccepted) error {
	return j.append(ctx, Event{Envelope: envelope, LambdaInvocationAccepted: event})
}

func (j *memoryJournal) AppendLambdaSourceBatchAccepted(ctx context.Context, envelope Envelope, event LambdaSourceBatchAccepted) error {
	return j.append(ctx, cloneEvent(Event{Envelope: envelope, LambdaSourceBatchAccepted: event}))
}

func (j *memoryJournal) AppendSQSMessageAccepted(ctx context.Context, envelope Envelope, event SQSMessageAccepted) error {
	return j.append(ctx, Event{Envelope: envelope, SQSMessageAccepted: event})
}

func (j *memoryJournal) AppendLogsBatchAccepted(ctx context.Context, envelope Envelope, event LogsBatchAccepted) error {
	return j.append(ctx, Event{Envelope: envelope, LogsBatchAccepted: event})
}

func (j *memoryJournal) LookupAPICalls(ctx context.Context, query APICallQuery) (APICallPage, error) {
	page := APICallPage{Events: []Event{}, MaxSequence: query.MaxSequence}
	err := j.store.View(ctx, func(events *[]Event, _ *memory.Transaction) error {
		if page.MaxSequence == 0 {
			page.MaxSequence = int64(len(*events))
		}
		for _, event := range *events {
			if event.APICallCompleted == nil || event.APICallCompleted.Category != CategoryManagement || event.Sequence > page.MaxSequence || event.Partition != query.Partition || event.AccountID != query.AccountID || event.Region != query.Region || event.At.Before(query.Start) || event.At.After(query.End) {
				continue
			}
			if query.Before != nil && (event.At.After(query.Before.At) || event.At.Equal(query.Before.At) && event.Sequence >= query.Before.Sequence) {
				continue
			}
			if matchesAPICall(*event.APICallCompleted, query.AttributeKey, query.AttributeValue) {
				page.Events = append(page.Events, event)
			}
		}
		slices.SortFunc(page.Events, func(a, b Event) int {
			if order := b.At.Compare(a.At); order != 0 {
				return order
			}
			if a.Sequence > b.Sequence {
				return -1
			}
			if a.Sequence < b.Sequence {
				return 1
			}
			return 0
		})
		page.Events = page.Events[:min(query.Limit, len(page.Events))]
		for i := range page.Events {
			page.Events[i] = cloneEvent(page.Events[i])
		}
		return nil
	})
	return page, err
}

func matchesAPICall(call APICallCompleted, key, value string) bool {
	switch key {
	case "":
		return true
	case "EventId":
		return call.EventID == value
	case "EventName":
		return call.EventName == value
	case "EventSource":
		return call.EventSource == value
	case "ReadOnly":
		return strconv.FormatBool(call.ReadOnly) == value
	case "Username":
		return call.Identity.UserName == value
	case "AccessKeyId":
		return call.Identity.AccessKeyID == value
	case "ResourceType", "ResourceName":
		return slices.ContainsFunc(call.Resources, func(r APIResource) bool {
			return key == "ResourceType" && r.Type == value || key == "ResourceName" && r.Name == value
		})
	default:
		return false
	}
}

func (j *memoryJournal) AppendHandshakeChanged(ctx context.Context, envelope Envelope, change HandshakeChanged) error {
	return j.append(ctx, Event{Envelope: envelope, HandshakeChanged: change})
}

func (j *memoryJournal) AppendEffectivePolicyChanged(ctx context.Context, envelope Envelope, change EffectivePolicyChanged) error {
	return j.append(ctx, Event{Envelope: envelope, EffectivePolicyChanged: change})
}
