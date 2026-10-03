package logs

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/internal/services/logs/filterpattern"
)

type subscriptionEvent struct {
	ID              string            `json:"id"`
	Timestamp       int64             `json:"timestamp"`
	Message         string            `json:"message"`
	ExtractedFields map[string]string `json:"extractedFields,omitempty"`
}
type subscriptionMessage struct {
	MessageType         string              `json:"messageType"`
	Owner               string              `json:"owner"`
	LogGroup            string              `json:"logGroup"`
	LogStream           string              `json:"logStream"`
	SubscriptionFilters []string            `json:"subscriptionFilters"`
	LogEvents           []subscriptionEvent `json:"logEvents"`
}

func subscriptionPayload(message subscriptionMessage) ([]byte, error) {
	var body bytes.Buffer
	zipped := gzip.NewWriter(&body)
	if err := json.NewEncoder(zipped).Encode(message); err != nil {
		return nil, err
	}
	if err := zipped.Close(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

// subscriptionControl is sent through the same real Kinesis write command as
// data; Lambda preflight remains a permission check without invoking user code.
func (s *Service) subscriptionControl(group GroupKey, sub SubscriptionRecord) (SubscriptionDelivery, error) {
	if strings.Contains(sub.DestinationARN, ":lambda:") {
		return SubscriptionDelivery{Group: group, DestinationARN: sub.DestinationARN}, nil
	}
	payload, err := subscriptionPayload(subscriptionMessage{MessageType: "CONTROL_MESSAGE", Owner: "CloudwatchLogs", LogGroup: "", LogStream: "", SubscriptionFilters: []string{}, LogEvents: []subscriptionEvent{{ID: "", Timestamp: s.clock.Now().UnixMilli(), Message: "CWL CONTROL MESSAGE: Checking health of destination Kinesis stream."}}})
	return SubscriptionDelivery{Group: group, DestinationARN: sub.DestinationARN, TargetARN: sub.TargetARN, RoleARN: sub.RoleARN, RoleSourceARN: sub.RoleSourceARN, PartitionKey: subscriptionPartitionKey(GroupKey{Scope: Scope{AccountID: "CloudwatchLogs"}}, "", "ByLogStream"), Payload: payload}, err
}

func subscriptionPartitionKey(group GroupKey, stream, distribution string) string {
	if distribution == "Random" {
		return uuid.NewString()
	}
	// Native captures for alpha/beta and CONTROL_MESSAGE match this hash.
	sum := md5.Sum([]byte(group.AccountID + ":" + group.Name + ":" + stream))
	return hex.EncodeToString(sum[:])
}

// enqueueSubscriptions shares ingestion's transaction and snapshots only accepted
// matching events. One PutLogEvents batch becomes at most one batch per filter;
// this local batching choice does not claim AWS's variable aggregation cadence.
func (s *Service) enqueueSubscriptions(tx Transaction, g GroupRecord, stream string, rows []SubscriptionRecord, events []EventRecord, parent string) *awswire.Error {
	// TODO: Comeback capture native oversized/high-entropy subscription batching,
	// including a single event that exceeds Lambda admission after gzip/base64,
	// before choosing splitting or permanent failure. Preserve real target errors.
	if len(events) == 0 {
		return nil
	}
	now := s.clock.Now()
	m := awsctx.FromContext(tx.Context())
	for _, sub := range rows {
		if now.Before(sub.DisabledUntil) {
			continue
		}
		if strings.Contains(sub.DestinationARN, ":logs:") {
			key, w := destinationARN(sub.DestinationARN)
			if w != nil {
				return w
			}
			d, err := tx.Destination(key)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return wireError(err)
			}
			sub.TargetARN, sub.RoleARN = d.TargetARN, d.RoleARN
		}
		selection, err := filterpattern.CompileSelection(sub.FieldSelection)
		if err != nil {
			return storageFailure()
		}
		if !selection.Match(g.Key.AccountID, g.Key.Region) {
			continue
		}
		pattern, err := filterpattern.Compile(sub.Pattern)
		if err != nil {
			return storageFailure()
		}
		message := subscriptionMessage{MessageType: "DATA_MESSAGE", Owner: g.Key.AccountID, LogGroup: g.Key.Name, LogStream: stream, SubscriptionFilters: []string{sub.Key.Name}}
		var fields map[string]string
		if len(sub.EmitSystemFields) > 0 {
			fields = make(map[string]string, len(sub.EmitSystemFields))
			for _, field := range sub.EmitSystemFields {
				switch field {
				case "@aws.account":
					fields[field] = g.Key.AccountID
				case "@aws.region":
					fields[field] = g.Key.Region
				case "@source.log":
					fields[field] = g.Key.Name
				}
			}
		}
		for _, event := range events {
			if pattern.Match(event.Message) {
				message.LogEvents = append(message.LogEvents, subscriptionEvent{ID: event.ID, Timestamp: event.Timestamp, Message: event.Message, ExtractedFields: fields})
			}
		}
		if len(message.LogEvents) == 0 {
			continue
		}
		payload, err := subscriptionPayload(message)
		if err != nil {
			return storageFailure()
		}
		delivery := SubscriptionDelivery{ID: uuid.NewString(), SubscriptionID: sub.ID, Key: sub.Key, Group: g.Key, DestinationARN: sub.DestinationARN, TargetARN: sub.TargetARN, RoleARN: sub.RoleARN, RoleSourceARN: sub.RoleSourceARN, ParentEventID: parent, RequestID: m.RequestID, Payload: payload, Due: now, Expires: now.Add(24 * time.Hour), Version: 1}
		if sub.TargetARN != "" {
			delivery.PartitionKey = subscriptionPartitionKey(g.Key, stream, sub.Distribution)
		}
		if err := tx.PutSubscriptionDelivery(delivery); err != nil {
			return wireError(err)
		}
	}
	return nil
}

type subscriptionJobs struct{ service *Service }

func (j subscriptionJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	var found bool
	err := j.service.repository.View(ctx, func(r Reader) error { var err error; next, found, err = r.NextSubscriptionDelivery(); return err })
	return next, found, err
}
func (j subscriptionJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.service
	var selected SubscriptionDelivery
	eligible := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.SubscriptionDelivery(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		now := s.clock.Now()
		if current.Version != job.Version || current.Due.After(now) {
			return nil
		}
		sub, err := tx.Subscription(current.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if errors.Is(err, ErrNotFound) || sub.ID != current.SubscriptionID || !now.Before(current.Expires) {
			return tx.DeleteSubscriptionDelivery(current.ID)
		}
		if now.Before(sub.DisabledUntil) {
			current.Due = minTime(sub.DisabledUntil, current.Expires)
			current.Version++
			return tx.PutSubscriptionDelivery(current)
		}
		current.Version++
		if err := tx.PutSubscriptionDelivery(current); err != nil {
			return err
		}
		selected, eligible = current, true
		return nil
	})
	if err != nil || !eligible {
		return err
	}
	m := awsctx.Metadata{Partition: selected.Group.Partition, AccountID: selected.Group.AccountID, Region: selected.Group.Region, ParentEventID: selected.ParentEventID, RequestID: selected.RequestID}
	var result *awswire.Error
	if s.subscriptions == nil {
		result = unsupported("No subscription destination is configured.")
	} else {
		result = s.subscriptions.Send(awsctx.WithMetadata(ctx, m), selected)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.finishSubscriptionDelivery(ctx, selected, result)
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (s *Service) finishSubscriptionDelivery(ctx context.Context, selected SubscriptionDelivery, result *awswire.Error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.SubscriptionDelivery(selected.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != selected.Version || current.SubscriptionID != selected.SubscriptionID {
			return nil
		}
		sub, err := tx.Subscription(current.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if errors.Is(err, ErrNotFound) || sub.ID != current.SubscriptionID {
			return tx.DeleteSubscriptionDelivery(current.ID)
		}
		if result == nil {
			return tx.DeleteSubscriptionDelivery(current.ID)
		}
		now := s.clock.Now()
		if subscriptionNonretryable(result) {
			// AWS documents disablement for up to ten minutes. Exactly ten service-time
			// minutes is the local choice, not a measured native interval. Arrivals during
			// disablement are skipped; the rejected batch is not retried.
			sub.DisabledUntil = now.Add(10 * time.Minute)
			if err := tx.PutSubscription(sub); err != nil {
				return err
			}
			return tx.DeleteSubscriptionDelivery(current.ID)
		}
		current.Attempts++
		current.Version++
		// At-least-once target admission has a 24-hour retention bound. The bounded
		// exponential cadence is local; Lambda owns handler retries after acceptance.
		delay := min(time.Second*time.Duration(1<<min(current.Attempts-1, 9)), 5*time.Minute)
		current.Due = minTime(now.Add(delay), current.Expires)
		return tx.PutSubscriptionDelivery(current)
	})
}
func subscriptionNonretryable(w *awswire.Error) bool {
	switch w.Code {
	case "AccessDenied", "AccessDeniedException", "ResourceNotFoundException", "ResourceNotFound", "InvalidParameterValueException", "InvalidParameterException", "UnsupportedOperationException":
		return true
	}
	return w.StatusCode == 401 || w.StatusCode == 403 || w.StatusCode == 404
}
