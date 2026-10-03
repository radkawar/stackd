package sns

import (
	"context"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

type subscriptionDeletionJobs struct{ s *Service }

func (j subscriptionDeletionJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error { job, found, err = r.NextSubscriptionDeletion(); return err })
	return
}
func (j subscriptionDeletionJobs) Run(ctx context.Context, job scheduler.Job) error {
	parsed, err := arn.Parse(job.Key)
	if err != nil {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: parsed.Partition, AccountID: parsed.AccountID, Region: parsed.Region})
	key, rejected := subscriptionKey(ctx, job.Key)
	if rejected != nil {
		return rejected
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		sub, err := tx.Subscription(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if sub.Version != job.Version || sub.DeletionDue == nil || sub.DeletionDue.After(j.s.clock.Now()) {
			return nil
		}
		return tx.DeleteSubscription(key)
	})
}

type deliveryJobs struct{ s *Service }

func (j deliveryJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	err = j.s.repository.View(ctx, func(r Reader) error { job, found, err = r.NextDelivery(); return err })
	return
}
func (j deliveryJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var delivery DeliveryRecord
	var message MessageRecord
	var sub SubscriptionRecord
	var httpPolicy httpDeliveryPolicy
	var successRole, failureRole string
	ready := false
	err := s.repository.Update(ctx, func(r Transaction) error {
		var err error
		delivery, err = r.Delivery(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if delivery.Version != job.Version || delivery.Due.After(s.clock.Now()) {
			return nil
		}
		message, err = r.Message(delivery.Message)
		if err != nil {
			return err
		}
		sub, err = r.Subscription(delivery.Subscription)
		if err != nil {
			return err
		}
		if message.Type == "" && sub.State != "" {
			return r.DeleteDelivery(delivery.ID)
		}
		if message.Type != "" {
			token, err := r.Confirmation(message.Token)
			if errors.Is(err, ErrNotFound) || err == nil && !token.Expires.After(s.clock.Now()) {
				return r.DeleteDelivery(delivery.ID)
			}
			if err != nil {
				return err
			}
		}
		var topic TopicRecord
		if !delivery.DeadLetter && (s.feedback != nil || httpSubscription(sub.Protocol)) {
			topic, err = r.Topic(sub.Key.Topic)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if s.feedback != nil && topic.ID == sub.TopicID {
				protocol := sub.Protocol
				if protocol == "https" {
					protocol = "http"
				}
				successRole, failureRole = feedbackRoles(topic.Feedback[protocol], delivery.ID)
			}
		}
		if httpSubscription(sub.Protocol) && !delivery.DeadLetter {
			httpPolicy = effectiveHTTPPolicy(topic, sub)
			if httpPolicy.Throttle != nil {
				if sub.NextHTTPDelivery.After(s.clock.Now()) {
					delivery.Due, delivery.Version = sub.NextHTTPDelivery, delivery.Version+1
					return r.PutDelivery(delivery)
				}
				sub.NextHTTPDelivery = s.clock.Now().Add(time.Second / time.Duration(httpPolicy.Throttle.Rate))
				if err := r.PutSubscription(sub); err != nil {
					return err
				}
			}
		}
		ready = true
		return nil
	})
	if err != nil || !ready {
		return err
	}
	if s.delivery == nil {
		return errors.New("SNS endpoint delivery is not configured")
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: message.Topic.Partition, AccountID: message.Topic.AccountID, Region: message.Topic.Region, RequestID: identifier(), ParentEventID: message.ParentEventID, TraceHeader: passThroughTraceHeader(message.Publisher.TraceHeader), ServicePrincipal: awsctx.ServicePrincipal{Name: "sns.amazonaws.com", SourceARN: message.Topic.ARN(), Type: "AWSService"}})
	result := s.openMessage(ctx, &message, false)
	if result != nil {
		// Keep encrypted work recoverable; neither plaintext fallback nor a
		// DLQ send can bypass failure to open the retained source body.
		// TODO: Comeback calibrate native key-failure expiry, retry and metrics.
		return s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Delivery(delivery.ID)
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if current.Version != delivery.Version {
				return nil
			}
			current.Version++
			current.Due = s.clock.Now().Add(20 * time.Second)
			return tx.PutDelivery(current)
		})
	}
	body, attributes, result := s.deliveryPayload(message, sub, delivery.DeadLetter, delivery.Replayed)
	var outcome DeliveryResult
	var dwellTimeMillis int64
	if result == nil {
		protocol, endpoint := sub.Protocol, sub.Endpoint
		if delivery.DeadLetter {
			protocol, endpoint = "sqs", sub.RedriveARN
		}
		kind := message.Type
		if kind == "" {
			kind = "Notification"
		}
		payload := DeliveryMessage{Body: body, Attributes: attributes, SubscriptionRoleARN: sub.SubscriptionRoleARN, Type: kind, MessageID: message.Key.ID, TopicARN: message.Topic.ARN(), SubscriptionARN: sub.Key.ARN(), Raw: sub.RawMessageDelivery && message.Type == "" && !delivery.DeadLetter}
		payload.CaptureFeedback = successRole != "" || failureRole != ""
		if httpPolicy.Request != nil {
			payload.ContentType = httpPolicy.Request.ContentType
		}
		if message.SequenceNumber == "" || strings.HasSuffix(endpoint, ".fifo") {
			payload.MessageGroupID = message.MessageGroupID
		}
		if strings.HasSuffix(endpoint, ".fifo") {
			payload.MessageDeduplicationID = message.MessageDeduplicationID
		}
		if payload.CaptureFeedback {
			dwellTimeMillis = s.clock.Now().Sub(message.Published).Milliseconds()
		}
		outcome = s.delivery.Send(ctx, protocol, endpoint, payload)
		result = outcome.Error
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var feedbackRole string
	completed := false
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Delivery(delivery.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.Version != delivery.Version {
			return nil
		}
		// SNS treats non-retryable HTTP responses as completed deliveries,
		// including a native 400 response: Delivered=1, Failed=0, no DLQ.
		completedHTTP := !current.DeadLetter && httpSubscription(sub.Protocol) &&
			result != nil && result.Code == "HTTPDeliveryFailed" && !retryableDelivery(result)
		if result == nil || completedHTTP {
			completed, feedbackRole = true, successRole
			if err := s.stageDeliveryMetrics(tx, message.Topic, s.clock.Now(), current.DeadLetter, current.Replayed, true); err != nil {
				return err
			}
			return tx.DeleteDelivery(current.ID)
		}
		current.Attempts++
		current.Version++
		retries, delay := current.Attempts < 100015, deliveryRetryDelay(current.ID, current.Attempts)
		if httpPolicy.Retry != nil && !current.DeadLetter {
			retries = current.Attempts <= httpPolicy.Retry.Retries
			delay = httpRetryDelay(*httpPolicy.Retry, current.Attempts)
		}
		retrying := retryableDelivery(result) && retries
		// HTTP failure metrics include every failed attempt; managed endpoints
		// and dead-letter delivery count only their terminal outcome.
		if !retrying || !current.DeadLetter && httpSubscription(sub.Protocol) {
			feedbackRole = failureRole
			if err := s.stageDeliveryMetrics(tx, message.Topic, s.clock.Now(), current.DeadLetter, current.Replayed, false); err != nil {
				return err
			}
		}
		if retrying {
			current.Due = s.clock.Now().Add(delay)
			return tx.PutDelivery(current)
		}
		if message.Type != "" {
			return tx.DeleteDelivery(current.ID)
		}
		if !current.DeadLetter && sub.RedriveARN != "" {
			current.DeadLetter = true
			current.Attempts = 0
			current.Due = s.clock.Now()
			return tx.PutDelivery(current)
		}
		return tx.DeleteDelivery(current.ID)
	})
	if err == nil && feedbackRole != "" && outcome.StatusCode != 0 {
		s.recordFeedback(ctx, feedbackRole, &message, &sub, delivery.Attempts, dwellTimeMillis, outcome, completed)
	}
	return err
}

func retryableDelivery(result *awswire.Error) bool {
	return result.StatusCode >= 500 && result.StatusCode < 600 || result.StatusCode == 429 || strings.Contains(strings.ToLower(result.Code), "throttl") || result.Code == "RequestTimeout"
}

// Managed endpoints have immediate, pre-backoff, exponential and long-tail
// phases. Jitter is deterministic from retained delivery identity and attempt.
// TODO: Comeback calibrate SNS managed retry jitter and exact initial-attempt counting against native AWS; only terminal authorization redrive has native delivery evidence.
func deliveryRetryDelay(id string, attempt int) time.Duration {
	if attempt <= 3 {
		return 0
	}
	if attempt <= 5 {
		return time.Second
	}
	base := 20 * time.Second
	if attempt <= 15 {
		base = min(time.Second*time.Duration(1<<uint(attempt-6)), base)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	_, _ = h.Write([]byte(strconv.Itoa(attempt)))
	return time.Duration(h.Sum64() % uint64(base+1))
}
