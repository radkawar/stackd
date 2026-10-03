package sns

import (
	"context"
	"errors"
	"maps"
	"strconv"
	"strings"
	"unicode/utf8"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
)

const effectiveDeliveryPolicy = `{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false,"defaultRequestPolicy":{"headerContentType":"text/plain; charset=UTF-8"}}}`

func (s *Service) registerTopics() {
	register(s, "CreateTopic", s.createTopic)
	register(s, "DeleteTopic", s.deleteTopic)
	register(s, "GetTopicAttributes", s.getTopicAttributes)
	register(s, "SetTopicAttributes", s.setTopicAttributes)
	register(s, "ListTopics", s.listTopics)
}

func (s *Service) createTopic(ctx context.Context, in *api.CreateTopicInput) (out *api.CreateTopicOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "CreateTopic", in, &out, &rejected, false)
	name := value(in.Name)
	if mode, exists := in.Attributes["FifoTopic"]; exists && !strings.EqualFold(string(mode), "true") && !strings.EqualFold(string(mode), "false") {
		return nil, failure("InvalidParameter", "FifoTopic must be true or false")
	}
	fifo := strings.EqualFold(string(in.Attributes["FifoTopic"]), "true")
	if !validTopicName(name) || strings.HasSuffix(name, ".fifo") != fifo {
		return nil, failure("InvalidParameter", "Invalid parameter: Topic Name")
	}
	if value(in.DataProtectionPolicy) != "" {
		// TODO: Comeback — implement data-protection inspection and enforcement.
		return nil, unsupported("Topic data protection policies are not implemented.")
	}
	key := TopicKey{Scope: scopeFor(ctx), Name: name}
	tags, conditions, wire := tagInput(in.Tags)
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "CreateTopic", key.ARN(), nil, conditions, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if len(tags) != 0 {
			if err := s.authorize(tx, "TagResource", key.ARN(), nil, conditions, authorization.BoundPolicy{}); err != nil {
				return err
			}
		}
		previous, err := tx.Topic(key)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		topic := previous
		topic.Feedback = maps.Clone(previous.Feedback)
		if !exists {
			now := s.clock.Now()
			topic = TopicRecord{Key: key, ID: identifier(), Tags: tags, Created: now, Updated: now, FIFO: fifo}
			topic.Policy, err = s.bindTopicPolicy(tx.Context(), defaultTopicPolicy(key), key)
			if err != nil {
				return err
			}
		}
		for attribute, v := range in.Attributes {
			if attribute == "FifoTopic" {
				continue
			}
			if err := s.setTopicAttribute(tx.Context(), &topic, string(attribute), string(v)); err != nil {
				return err
			}
		}
		if exists {
			if topic.DisplayName != previous.DisplayName || topic.SignatureVersion != previous.SignatureVersion || topic.KmsMasterKeyID != previous.KmsMasterKeyID || topic.Policy.Document != previous.Policy.Document || topic.ContentBasedDeduplication != previous.ContentBasedDeduplication || topic.FifoThroughputScope != previous.FifoThroughputScope || topic.DeliveryPolicy != previous.DeliveryPolicy || topic.TracingConfig != previous.TracingConfig {
				return failure("InvalidParameter", "Invalid parameter: Attributes Reason: Topic already exists with different attributes")
			}
			if !maps.Equal(topic.Feedback, previous.Feedback) {
				return failure("InvalidParameter", "Invalid parameter: Attributes Reason: Topic already exists with different attributes")
			}
			// Repeated creation rejects even an identical enabled archive policy;
			// omitting the attribute remains idempotent.
			if _, supplied := in.Attributes["ArchivePolicy"]; supplied && (topic.Archive != nil || previous.Archive != nil) {
				return failure("InvalidParameter", "Invalid parameter: Attributes Reason: Topic already exists with different attributes")
			}
			if len(in.Tags) != 0 && !maps.Equal(tags, previous.Tags) {
				return failure("InvalidParameter", "Invalid parameter: Tags Reason: Topic already exists with different tags")
			}
		} else {
			count, err := tx.TopicCount(key.Scope)
			if err != nil {
				return err
			}
			if count >= 100000 {
				return failure("TopicLimitExceeded", "The account has reached its topic limit.")
			}
			if err := tx.PutTopic(topic); err != nil {
				return err
			}
		}
		out = &api.CreateTopicOutput{TopicArn: str[api.TopicARN](key.ARN())}
		return s.recordCall(tx.Context(), "CreateTopic", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) deleteTopic(ctx context.Context, in *api.DeleteTopicInput) (out *api.DeleteTopicOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DeleteTopic", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.TopicArn))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := s.authorize(tx, "DeleteTopic", key.ARN(), topic.Tags, nil, topic.Policy); err != nil {
			return err
		}
		if exists {
			if topic.Archive != nil {
				return failure("InvalidState", "Invalid state: Cannot delete a topic with an ArchivePolicy")
			}
			if err := tx.OrphanTopicSubscriptions(topic.ID, s.clock.Now().Add(topicSubscriptionDeletionDelay)); err != nil {
				return err
			}
			if err := tx.DeleteTopic(key); err != nil {
				return err
			}
		}
		out = &api.DeleteTopicOutput{}
		return s.recordCall(tx.Context(), "DeleteTopic", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) getTopicAttributes(ctx context.Context, in *api.GetTopicAttributesInput) (out *api.GetTopicAttributesOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "GetTopicAttributes", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.TopicArn))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "GetTopicAttributes", key.ARN(), topic.Tags, nil, topic.Policy); err != nil {
			return err
		}
		document, err := s.renderPolicy(tx.Context(), topic.Policy)
		if err != nil {
			return err
		}
		count, pending, deleted := int64(0), int64(0), int64(0)
		query := TopicSubscriptionQuery{Topic: key, TopicID: topic.ID, Limit: 256}
		for {
			rows, err := tx.SubscriptionsByTopic(query)
			if err != nil {
				return err
			}
			for _, sub := range rows {
				switch sub.State {
				case "pending":
					pending++
				case "deleted":
					deleted++
				default:
					count++
				}
			}
			if len(rows) < query.Limit {
				break
			}
			query.After = rows[len(rows)-1].Key.ID
		}
		out = &api.GetTopicAttributesOutput{Attributes: api.TopicAttributesMap{
			"TopicArn": api.AttributeValue(key.ARN()), "Owner": api.AttributeValue(key.AccountID),
			"DisplayName": api.AttributeValue(topic.DisplayName), "Policy": api.AttributeValue(document),
			"EffectiveDeliveryPolicy": effectiveDeliveryPolicy,
			"SubscriptionsConfirmed":  api.AttributeValue(strconv.FormatInt(count, 10)),
			"SubscriptionsPending":    api.AttributeValue(strconv.FormatInt(pending, 10)), "SubscriptionsDeleted": api.AttributeValue(strconv.FormatInt(deleted, 10)),
		}}
		if topic.DeliveryPolicy != "" {
			out.Attributes["DeliveryPolicy"] = api.AttributeValue(topic.DeliveryPolicy)
			out.Attributes["EffectiveDeliveryPolicy"] = api.AttributeValue(effectiveHTTPTopicPolicyJSON(topic))
		}
		if topic.FIFO {
			out.Attributes["FifoTopic"] = "true"
			out.Attributes["ContentBasedDeduplication"] = api.AttributeValue(strconv.FormatBool(topic.ContentBasedDeduplication))
			if topic.FifoThroughputScope != "" {
				out.Attributes["FifoThroughputScope"] = api.AttributeValue(topic.FifoThroughputScope)
			}
		}
		if topic.Archive != nil {
			out.Attributes["ArchivePolicy"] = api.AttributeValue(topic.Archive.Policy)
			out.Attributes["BeginningArchiveTime"] = api.AttributeValue(notificationTimestamp(beginningArchiveTime(*topic.Archive, s.clock.Now())))
		}
		if topic.SignatureVersion != "" {
			out.Attributes["SignatureVersion"] = api.AttributeValue(topic.SignatureVersion)
		}
		if topic.KmsMasterKeyID != "" {
			out.Attributes["KmsMasterKeyId"] = api.AttributeValue(topic.KmsMasterKeyID)
		}
		if topic.TracingConfig != "" {
			out.Attributes["TracingConfig"] = api.AttributeValue(topic.TracingConfig)
		}
		feedbackAttributes(topic, out.Attributes)
		return s.recordCall(tx.Context(), "GetTopicAttributes", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) setTopicAttributes(ctx context.Context, in *api.SetTopicAttributesInput) (out *api.SetTopicAttributesOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "SetTopicAttributes", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.TopicArn))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "SetTopicAttributes", key.ARN(), topic.Tags, nil, topic.Policy); err != nil {
			return err
		}
		previousArchive := topic.Archive
		if err := s.setTopicAttribute(tx.Context(), &topic, value(in.AttributeName), value(in.AttributeValue)); err != nil {
			return err
		}
		topic.Updated = s.clock.Now()
		if err := tx.PutTopic(topic); err != nil {
			return err
		}
		if value(in.AttributeName) == "ArchivePolicy" && previousArchive != nil {
			if topic.Archive == nil {
				if err := tx.DeleteArchiveEntries(topic.ID); err != nil {
					return err
				}
			} else if topic.Archive.RetentionDays != previousArchive.RetentionDays {
				if err := tx.UpdateArchiveRetention(topic.ID, topic.Archive.RetentionDays, topic.Updated); err != nil {
					return err
				}
			}
		}
		out = &api.SetTopicAttributesOutput{}
		return s.recordCall(tx.Context(), "SetTopicAttributes", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) setTopicAttribute(ctx context.Context, topic *TopicRecord, name, v string) error {
	switch name {
	case "DisplayName":
		if !utf8.ValidString(v) || utf8.RuneCountInString(v) > 100 {
			return failure("InvalidParameter", "Invalid parameter: DisplayName")
		}
		topic.DisplayName = v
	case "SignatureVersion":
		if v != "1" && v != "2" {
			return failure("InvalidParameter", "Invalid parameter: SignatureVersion")
		}
		topic.SignatureVersion = v
	case "Policy":
		if v == topic.Policy.Document {
			return nil
		}
		bound, err := s.bindTopicPolicy(ctx, v, topic.Key)
		if err != nil {
			return err
		}
		topic.Policy = bound
	case "KmsMasterKeyId":
		topic.KmsMasterKeyID = v
	case "FifoTopic", "ContentBasedDeduplication", "FifoThroughputScope":
		if !topic.FIFO {
			return failure("InvalidParameter", "Invalid parameter: AttributeName")
		}
		switch name {
		case "FifoTopic":
			if !strings.EqualFold(v, "true") {
				return failure("InvalidParameter", "Modifying topic type is not supported")
			}
		case "ContentBasedDeduplication":
			topic.ContentBasedDeduplication = strings.EqualFold(v, "true")
			if !strings.EqualFold(v, "true") && !strings.EqualFold(v, "false") {
				return failure("InvalidParameter", "ContentBasedDeduplication must be true or false")
			}
		case "FifoThroughputScope":
			if v != "Topic" && v != "MessageGroup" || topic.FifoThroughputScope == "MessageGroup" && v == "Topic" {
				return failure("InvalidParameter", "Invalid FifoThroughputScope transition")
			}
			topic.FifoThroughputScope = v
		}
	case "ArchivePolicy":
		if wire := s.setArchivePolicy(topic, v); wire != nil {
			return wire
		}
	case "BeginningArchiveTime":
		return failure("InvalidParameter", "Invalid parameter: AttributeName")
	case "DeliveryPolicy":
		policy, wire := validateHTTPPolicy(v, false, true)
		if wire != nil {
			return wire
		}
		topic.DeliveryPolicy = policy
	case "TracingConfig":
		switch v {
		case "PassThrough":
			topic.TracingConfig = v
		case "Active":
			// TODO: Comeback implement SNS-owned X-Ray segment emission and resource-policy authorization before admitting Active; parent rewriting alone is not active tracing.
			return unsupported("SNS Active tracing requires SNS-owned X-Ray segment emission and is not implemented.")
		default:
			return failure("InvalidParameter", "Invalid parameter: Invalid tracing config value: "+v)
		}
	default:
		if protocol, attribute := feedbackAttribute(name); protocol != "" {
			return s.setFeedbackAttribute(ctx, topic, protocol, attribute, v)
		}
		if strings.HasPrefix(name, "Application") && (strings.HasSuffix(name, "FeedbackRoleArn") || strings.HasSuffix(name, "SuccessFeedbackSampleRate")) {
			return unsupported("Mobile platform feedback requires a supported mobile delivery endpoint.")
		}
		return failure("InvalidParameter", "Invalid parameter: AttributeName")
	}
	return nil
}

func (s *Service) listTopics(ctx context.Context, in *api.ListTopicsInput) (out *api.ListTopicsOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListTopics", in, &out, &rejected, false)
	scope := scopeFor(ctx)
	collection := (TopicKey{Scope: scope}).ARN() + "/ListTopics"
	after, wire := decodeTopicCursor(in.NextToken, collection)
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "ListTopics", "*", nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		rows, err := tx.Topics(TopicQuery{Scope: scope, After: after, Limit: 101})
		if err != nil {
			return err
		}
		out = &api.ListTopicsOutput{Topics: api.TopicsList{}}
		if len(rows) > 100 {
			rows = rows[:100]
			out.NextToken = encodeTopicCursor(collection, rows[99].Key.Name)
		}
		for _, topic := range rows {
			out.Topics = append(out.Topics, api.Topic{TopicArn: str[api.TopicARN](topic.Key.ARN())})
		}
		return s.recordCall(tx.Context(), "ListTopics", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
