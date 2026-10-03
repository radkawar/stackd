package sns

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/messageattribute"
	"stackd/internal/services/sns/filterpolicy"
)

// CheckPublish evaluates a destination preflight without publishing a synthetic
// notification. It shares the ordinary topic lookup and policy boundary.
func (s *Service) CheckPublish(ctx context.Context, topicARN string) *awswire.Error {
	key, rejected := topicKey(ctx, topicARN)
	if rejected != nil {
		return rejected
	}
	err := s.repository.View(ctx, func(r Reader) error {
		_, err := s.publicationTopic(r, key)
		return err
	})
	return wireError(err)
}

// publicationTopic applies IAM before exposing a missing topic. A foreign
// publisher has no resource grant after deletion, even with identity permission.
func (s *Service) publicationTopic(r Reader, key TopicKey) (TopicRecord, error) {
	topic, err := r.Topic(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return TopicRecord{}, err
	}
	if denied := s.authorize(r, "Publish", key.ARN(), topic.Tags, nil, topic.Policy); denied != nil {
		return TopicRecord{}, denied
	}
	return topic, err
}

// Publish is the ordinary authorized SNS command used by both the generated
// frontend and service producers. Acceptance commits messages, delivery intents
// and the API outcome together; endpoints run only after that transaction.
func (s *Service) Publish(ctx context.Context, in *api.PublishInput) (out *api.PublishOutput, rejected *awswire.Error) {
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	defer finishCall(s, ctx, "Publish", in, &out, &rejected, false)
	if in.PhoneNumber != nil || in.TargetArn != nil {
		// TODO: Comeback implement direct SMS and mobile platform publication.
		return nil, unsupported("SNS SMS and mobile platform publication are not implemented.")
	}
	key, rejected := topicKey(ctx, value(in.TopicArn))
	if rejected != nil {
		return nil, rejected
	}
	message, size, validationErr := normalizePublication(api.PublishBatchRequestEntry{Message: in.Message, Subject: in.Subject, MessageAttributes: in.MessageAttributes, MessageStructure: in.MessageStructure, MessageGroupId: in.MessageGroupId, MessageDeduplicationId: in.MessageDeduplicationId})
	if validationErr != nil {
		return nil, wireError(validationErr)
	}
	signer, keyID, err := s.publicationSigner(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	original := message
	err = s.updatePublication(ctx, func(tx Transaction, keys *publicationKeys) error {
		message = original
		topic, err := s.publicationTopic(tx, key)
		if err != nil {
			return err
		}
		if err := validateTopicPublication(topic, message); err != nil {
			return err
		}
		if err := keys.require(topic); err != nil {
			return err
		}
		var now time.Time
		if topic.FIFO {
			now = s.clock.Now()
			if err := tx.DeleteExpiredDeduplication(topic.ID, now); err != nil {
				return err
			}
		}
		fresh, err := acceptPublication(tx, &topic, &message, now)
		if err != nil {
			return err
		}
		accepted := []publication(nil)
		if fresh {
			accepted = []publication{message}
		}
		if err := s.fanout(tx, topic, accepted, signer, keyID, size, keys); err != nil {
			return err
		}
		out = &api.PublishOutput{MessageId: str[api.MessageId](message.Key.ID)}
		if topic.FIFO {
			out.SequenceNumber = str[api.String](message.SequenceNumber)
		}
		return s.recordCall(tx.Context(), "Publish", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) publishBatch(ctx context.Context, in *api.PublishBatchInput) (out *api.PublishBatchOutput, rejected *awswire.Error) {
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	defer finishCall(s, ctx, "PublishBatch", in, &out, &rejected, false)
	if len(in.PublishBatchRequestEntries) == 0 {
		return nil, failure("EmptyBatchRequest", "The batch request contains no entries.")
	}
	if len(in.PublishBatchRequestEntries) > 10 {
		return nil, failure("TooManyEntriesInBatchRequest", "The batch request contains more than 10 entries.")
	}
	key, rejected := topicKey(ctx, value(in.TopicArn))
	if rejected != nil {
		return nil, rejected
	}
	seen := make(map[string]bool, len(in.PublishBatchRequestEntries))
	messages := make([]publication, 0, len(in.PublishBatchRequestEntries))
	entryIDs := make([]string, 0, len(in.PublishBatchRequestEntries))
	out = &api.PublishBatchOutput{Successful: api.PublishBatchResultEntryList{}, Failed: api.BatchResultErrorEntryList{}}
	total := 0
	for _, entry := range in.PublishBatchRequestEntries {
		id := value(entry.Id)
		if !batchEntryIDPattern.MatchString(id) {
			return nil, failure("InvalidBatchEntryId", "Invalid batch entry Id.")
		}
		if seen[id] {
			return nil, failure("BatchEntryIdsNotDistinct", "Two or more batch entries have the same Id.")
		}
		seen[id] = true
		message, size, validationErr := normalizePublication(entry)
		total += size
		if total > maximumMessageBytes {
			return nil, failure("BatchRequestTooLong", "The length of all batch messages exceeds 262144 bytes.")
		}
		if validationErr != nil {
			wire := wireError(validationErr)
			// Native attribute admission fails the entire request, unlike an
			// invalid Subject or empty message in an otherwise valid batch.
			var attributeErr publicationAttributeError
			if errors.As(validationErr, &attributeErr) {
				return nil, wire
			}
			out.Failed = append(out.Failed, api.BatchResultErrorEntry{Id: str[api.String](id), Code: str[api.String](wire.Code), Message: str[api.String](wire.Message), SenderFault: ptr(api.Boolean(wire.StatusCode < 500))})
			continue
		}
		messages = append(messages, message)
		entryIDs = append(entryIDs, id)
	}
	signer, keyID, err := s.publicationSigner(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	originalMessages := append([]publication(nil), messages...)
	originalFailed := append(api.BatchResultErrorEntryList(nil), out.Failed...)
	err = s.updatePublication(ctx, func(tx Transaction, keys *publicationKeys) error {
		copy(messages, originalMessages)
		out.Successful = api.PublishBatchResultEntryList{}
		out.Failed = append(api.BatchResultErrorEntryList{}, originalFailed...)
		topic, err := s.publicationTopic(tx, key)
		if err != nil {
			return err
		}
		if topic.FIFO && len(out.Failed) > 0 {
			return failure(value(out.Failed[0].Code), value(out.Failed[0].Message))
		}
		var now time.Time
		if topic.FIFO {
			for _, message := range messages {
				if err := validateTopicPublication(topic, message); err != nil {
					return err
				}
			}
			now = s.clock.Now()
			if err := tx.DeleteExpiredDeduplication(topic.ID, now); err != nil {
				return err
			}
		}
		if err := keys.require(topic); err != nil {
			return err
		}
		accepted := make([]publication, 0, len(messages))
		for i := range messages {
			if !topic.FIFO {
				if err := validateTopicPublication(topic, messages[i]); err != nil {
					wire := wireError(err)
					out.Failed = append(out.Failed, api.BatchResultErrorEntry{Id: str[api.String](entryIDs[i]), Code: str[api.String](wire.Code), Message: str[api.String](wire.Message), SenderFault: ptr(api.Boolean(true))})
					continue
				}
			}
			fresh, err := acceptPublication(tx, &topic, &messages[i], now)
			if err != nil {
				return err
			}
			if fresh {
				accepted = append(accepted, messages[i])
			}
			result := api.PublishBatchResultEntry{Id: str[api.String](entryIDs[i]), MessageId: str[api.MessageId](messages[i].Key.ID)}
			if topic.FIFO {
				result.SequenceNumber = str[api.String](messages[i].SequenceNumber)
			}
			out.Successful = append(out.Successful, result)
		}
		if err := s.fanout(tx, topic, accepted, signer, keyID, total, keys); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PublishBatch", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func validateTopicPublication(topic TopicRecord, message publication) error {
	if !topic.FIFO {
		if message.deduplicationSet {
			return failure("InvalidParameter", "MessageDeduplicationId is not valid for a standard topic.")
		}
		return nil
	}
	if message.MessageGroupID == "" {
		return failure("InvalidParameter", "The MessageGroupId parameter is required for FIFO topics")
	}
	if message.deduplicationSet && !messageattribute.ValidMessageID(message.MessageDeduplicationID) {
		return failure("InvalidParameter", "Invalid MessageDeduplicationId")
	}
	if message.MessageDeduplicationID == "" && !topic.ContentBasedDeduplication {
		return failure("InvalidParameter", "The topic requires ContentBasedDeduplication or MessageDeduplicationId")
	}
	return nil
}

// Admission owns the receipt even if every subscription filters the publication.
// Retrying a duplicate neither extends its window nor creates a new delivery.
func acceptPublication(tx Transaction, topic *TopicRecord, message *publication, now time.Time) (bool, error) {
	if !topic.FIFO {
		message.Key.ID = identifier()
		return true, nil
	}
	if message.MessageDeduplicationID == "" {
		hash := sha256.Sum256([]byte(message.originalBody))
		message.MessageDeduplicationID = hex.EncodeToString(hash[:])
	}
	key := DeduplicationKey{TopicID: topic.ID, ID: message.MessageDeduplicationID}
	if topic.FifoThroughputScope == "MessageGroup" {
		key.Group = message.MessageGroupID
	}
	previous, err := tx.Deduplication(key)
	if err == nil {
		message.Key.ID, message.SequenceNumber = previous.MessageID, previous.SequenceNumber
		return false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return false, err
	}
	sequence, err := tx.NextTopicSequence(topic.Key)
	if err != nil {
		return false, err
	}
	message.Key.ID = identifier()
	message.SequenceNumber = strconv.FormatUint(sequence, 10)
	return true, tx.PutDeduplication(DeduplicationRecord{Key: key, MessageID: message.Key.ID, SequenceNumber: message.SequenceNumber, Expires: now.Add(5 * time.Minute)})
}

func (s *Service) publicationSigner(ctx context.Context) (*rsa.PrivateKey, string, error) {
	if s.publicEndpoint == "" {
		return nil, "", nil
	}
	key, record, err := s.signingMaterial(ctx, true)
	return key, record.ID, err
}

func (s *Service) fanout(tx Transaction, topic TopicRecord, messages []publication, signer *rsa.PrivateKey, keyID string, size int, keys *publicationKeys) error {
	now := s.clock.Now()
	metadata := awsctx.FromContext(tx.Context())
	// Native batch counters contain one sample: accepted-message count and
	// whole-request bytes, including per-entry failures but excluding Subject.
	if err := s.stageMetric(tx, topic.Key, now, metricPublished, int64(len(messages)), 1); err != nil {
		return err
	}
	if err := s.stageMetric(tx, topic.Key, now, metricPublishSize, int64(size), 1); err != nil {
		return err
	}
	for i := range messages {
		messages[i].Topic = topic.Key
		messages[i].Published = now
		messages[i].ParentEventID = apievents.EventID(tx.Context())
		messages[i].RequestID = metadata.RequestID
		messages[i].SignatureVersion = topic.SignatureVersion
		if messages[i].SignatureVersion == "" {
			messages[i].SignatureVersion = "1"
		}
	}
	retained := make(map[MessageKey]struct{}, len(messages))
	if topic.Archive != nil {
		for i := range messages {
			key, err := s.archivePublication(tx, topic, &messages[i], keys)
			if err != nil {
				return err
			}
			retained[key] = struct{}{}
		}
	}
	var filterResults [filterpolicy.MatchResultCount]int64
	// Topic deletion can retain active routes from the previous incarnation.
	// Cancelled subscriptions remain ineligible even if an old token is accepted.
	query := TopicSubscriptionQuery{Topic: topic.Key, Limit: 256}
	for {
		subscriptions, err := tx.SubscriptionsByTopic(query)
		if err != nil {
			return err
		}
		for _, sub := range subscriptions {
			if sub.State != "" || sub.Replay.Paused {
				continue
			}
			policy, err := filterpolicy.Compile(sub.FilterPolicy, sub.FilterScope)
			if err != nil {
				return err
			}
			for i := range messages {
				key, body := messages[i].Key, messages[i].Body
				if override, ok := messages[i].protocolBodies[sub.Protocol]; ok {
					key.Protocol, body = sub.Protocol, override
				}
				// Body filters inspect the selected native protocol payload,
				// not the original JSON protocol map or a different default.
				match := policy.Match(body, messages[i].Attributes)
				filterResults[match]++
				if match != filterpolicy.Matched {
					continue
				}
				if s.delivery == nil {
					return unsupported("SNS endpoint delivery is not configured.")
				}
				if signer == nil && !topic.FIFO {
					return unsupported("SNS delivery requires a trusted PublicEndpoint for native signing certificates.")
				}
				if _, exists := retained[key]; !exists {
					message := messages[i].MessageRecord
					message.Key, message.Body = key, body
					if !topic.FIFO {
						if err := signNotification(&message, signer, keyID); err != nil {
							return err
						}
					}
					if err := keys.seal(topic, &message); err != nil {
						return err
					}
					if err := tx.PutMessage(message); err != nil {
						return err
					}
					retained[key] = struct{}{}
				}
				delivery := DeliveryRecord{Message: key, Subscription: sub.Key, Due: now}
				if topic.FIFO {
					delivery.FIFOGroup = messages[i].MessageGroupID
				}
				if err := enqueueDelivery(tx, delivery); err != nil {
					return err
				}
			}
		}
		if len(subscriptions) < query.Limit {
			return s.stageFilterMetrics(tx, topic.Key, now, filterResults)
		}
		query.After = subscriptions[len(subscriptions)-1].Key.ID
	}
}
