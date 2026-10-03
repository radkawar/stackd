package sns

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
	"stackd/internal/services/sns/filterpolicy"
)

func (s *Service) getSubscriptionAttributes(ctx context.Context, in *api.GetSubscriptionAttributesInput) (out *api.GetSubscriptionAttributesOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "GetSubscriptionAttributes", in, &out, &rejected, false)
	key, wire := subscriptionKey(ctx, value(in.SubscriptionArn))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		sub, err := tx.Subscription(key)
		if errors.Is(err, ErrNotFound) {
			return failure("NotFound", "Subscription does not exist", 404)
		}
		if err != nil {
			return err
		}
		if err := s.authorizeSubscription(tx, "GetSubscriptionAttributes", sub); err != nil {
			return err
		}
		attributes := api.SubscriptionAttributesMap{
			"SubscriptionArn":              api.AttributeValue(sub.Key.ARN()),
			"TopicArn":                     api.AttributeValue(sub.Key.Topic.ARN()),
			"Owner":                        api.AttributeValue(sub.Owner),
			"SubscriptionPrincipal":        api.AttributeValue(sub.PrincipalARN),
			"Protocol":                     api.AttributeValue(sub.Protocol),
			"Endpoint":                     api.AttributeValue(sub.Endpoint),
			"PendingConfirmation":          api.AttributeValue(strconv.FormatBool(sub.State == "pending")),
			"ConfirmationWasAuthenticated": api.AttributeValue(strconv.FormatBool(sub.ConfirmationAuthenticated)),
			"RawMessageDelivery":           api.AttributeValue(strconv.FormatBool(sub.RawMessageDelivery)),
		}
		if sub.SubscriptionRoleARN != "" {
			attributes["SubscriptionRoleArn"] = api.AttributeValue(sub.SubscriptionRoleARN)
		}
		if httpSubscription(sub.Protocol) {
			topic, err := tx.Topic(sub.Key.Topic)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			attributes["EffectiveDeliveryPolicy"] = api.AttributeValue(httpEffectivePolicyJSON(effectiveHTTPPolicy(topic, sub)))
			if sub.DeliveryPolicy != "" {
				attributes["DeliveryPolicy"] = api.AttributeValue(sub.DeliveryPolicy)
			}
		}
		if sub.FilterPolicy != "" {
			attributes["FilterPolicy"] = api.AttributeValue(sub.FilterPolicy)
		}
		if sub.FilterScope != "" {
			attributes["FilterPolicyScope"] = api.AttributeValue(sub.FilterScope)
		}
		if sub.RedriveARN != "" {
			attributes["RedrivePolicy"] = api.AttributeValue(redrivePolicyJSON(sub.RedriveARN))
		}
		if sub.Replay.Policy != "" {
			attributes["ReplayPolicy"] = api.AttributeValue(sub.Replay.Policy)
			attributes["ReplayStatus"] = api.AttributeValue(sub.Replay.Status)
		}
		out = &api.GetSubscriptionAttributesOutput{Attributes: attributes}
		return s.recordCall(tx.Context(), "GetSubscriptionAttributes", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) setSubscriptionAttributes(ctx context.Context, in *api.SetSubscriptionAttributesInput) (out *api.SetSubscriptionAttributesOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "SetSubscriptionAttributes", in, &out, &rejected, false)
	key, wire := subscriptionKey(ctx, value(in.SubscriptionArn))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		previous, err := tx.Subscription(key)
		if errors.Is(err, ErrNotFound) {
			return failure("NotFound", "Subscription does not exist", 404)
		}
		if err != nil {
			return err
		}
		if err := s.authorizeSubscription(tx, "SetSubscriptionAttributes", previous); err != nil {
			return err
		}
		sub := previous
		attributes := api.SubscriptionAttributesMap{api.AttributeName(value(in.AttributeName)): api.AttributeValue(value(in.AttributeValue))}
		if wire := s.applySubscriptionAttributes(tx, &sub, attributes); wire != nil {
			return wire
		}
		if value(in.AttributeName) == "SubscriptionRoleArn" {
			if err := s.authorizeSubscriptionRole(tx.Context(), sub); err != nil {
				return err
			}
		}
		if err := subscriptionFilterQuota(tx, previous, sub); err != nil {
			return err
		}
		sub.Version++
		if err := tx.PutSubscription(sub); err != nil {
			return err
		}
		out = &api.SetSubscriptionAttributesOutput{}
		return s.recordCall(tx.Context(), "SetSubscriptionAttributes", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

// Work on a value copy and validate the final policy/scope pair, so request-map
// iteration order cannot change acceptance or leave a partially updated record.
func (s *Service) applySubscriptionAttributes(r Reader, sub *SubscriptionRecord, attributes api.SubscriptionAttributesMap) *awswire.Error {
	next := *sub
	policy, hasPolicy := attributes["FilterPolicy"]
	scope, hasScope := attributes["FilterPolicyScope"]
	if hasScope {
		if scope != "MessageAttributes" && scope != "MessageBody" {
			return failure("InvalidParameter", "Invalid parameter: FilterPolicyScope. Please use either MessageBody or MessageAttributes")
		}
		next.FilterScope = string(scope)
	}
	if hasPolicy {
		next.FilterPolicy = string(policy)
	}
	if hasPolicy || hasScope {
		if _, err := filterpolicy.Compile(next.FilterPolicy, next.FilterScope); err != nil {
			return failure("InvalidParameter", "Invalid parameter: FilterPolicy: "+err.Error())
		}
		if hasPolicy {
			// Preserve numbers exactly, sort object keys, and compact once at the
			// boundary. Both delivery and quota accounting consume this value.
			decoder := json.NewDecoder(strings.NewReader(next.FilterPolicy))
			decoder.UseNumber()
			var document map[string]any
			if err := decoder.Decode(&document); err != nil || document == nil {
				return failure("InvalidParameter", "Invalid parameter: FilterPolicy must be a JSON object")
			}
			if len(document) == 0 {
				next.FilterPolicy = ""
			} else {
				canonical, err := json.Marshal(document)
				if err != nil {
					return failure("InvalidParameter", "Invalid parameter: FilterPolicy: "+err.Error())
				}
				next.FilterPolicy = string(canonical)
				if next.FilterScope == "" {
					next.FilterScope = "MessageAttributes"
				}
			}
		}
	}
	for name, v := range attributes {
		switch name {
		case "FilterPolicy", "FilterPolicyScope":
		case "RawMessageDelivery":
			if next.Protocol != "sqs" && next.Protocol != "firehose" && !httpSubscription(next.Protocol) {
				return failure("InvalidParameter", "Invalid parameter: RawMessageDelivery is supported only for SQS and HTTP/S subscriptions")
			}
			if v != "true" && v != "false" {
				return failure("InvalidParameter", "Invalid parameter: RawMessageDelivery. Must be true or false.")
			}
			next.RawMessageDelivery = v == "true"
		case "RedrivePolicy":
			arn, wire := subscriptionRedriveARN(next, string(v))
			if wire != nil {
				return wire
			}
			next.RedriveARN = arn
		case "DeliveryPolicy":
			if !httpSubscription(next.Protocol) {
				return failure("InvalidParameter", "DeliveryPolicy is supported only for HTTP/S subscriptions.")
			}
			next.DeliveryPolicy = string(v)
		case "SubscriptionRoleArn":
			if next.Protocol != "firehose" {
				return failure("InvalidParameter", "SubscriptionRoleArn is supported only for Firehose subscriptions.")
			}
			next.SubscriptionRoleARN = string(v)
		case "ReplayPolicy":
			if wire := s.setReplayPolicy(r, &next, string(v)); wire != nil {
				return wire
			}
		case "ReplayStatus":
			return failure("InvalidParameter", "Invalid parameter: AttributeName")
		default:
			return failure("InvalidParameter", "Invalid parameter: AttributeName")
		}
	}
	if httpSubscription(next.Protocol) && next.DeliveryPolicy != "" {
		policy, wire := validateHTTPPolicy(next.DeliveryPolicy, next.RawMessageDelivery, false)
		if wire != nil {
			return wire
		}
		next.DeliveryPolicy = policy
	}
	*sub = next
	return nil
}

func redrivePolicyJSON(targetARN string) string {
	// This closed shape contains only a string and cannot fail JSON encoding.
	document, _ := json.Marshal(struct {
		TargetARN string `json:"deadLetterTargetArn"`
	}{targetARN})
	return string(document)
}

func subscriptionRedriveARN(sub SubscriptionRecord, document string) (string, *awswire.Error) {
	if document == "" {
		return "", nil
	}
	var policy map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &policy); err != nil || policy == nil {
		return "", failure("InvalidParameter", "Invalid parameter: RedrivePolicy must be a JSON object")
	}
	if len(policy) == 0 {
		return "", nil
	}
	var arn string
	if len(policy) != 1 || json.Unmarshal(policy["deadLetterTargetArn"], &arn) != nil || arn == "" {
		return "", failure("InvalidParameter", "Invalid parameter: RedrivePolicy requires deadLetterTargetArn")
	}
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != sub.Key.Topic.Partition || parts[2] != "sqs" || parts[3] != sub.Key.Topic.Region || parts[4] != sub.Owner || len(parts[5]) > 80 || !subscriptionQueueNamePattern.MatchString(parts[5]) {
		return "", failure("InvalidParameter", "RedrivePolicy must target an SQS queue in the subscription owner's account and Region")
	}
	if strings.HasSuffix(sub.Key.Topic.Name, ".fifo") && strings.HasSuffix(sub.Endpoint, ".fifo") != strings.HasSuffix(arn, ".fifo") {
		return "", failure("InvalidParameter", "RedrivePolicy queue type must match the FIFO topic subscription endpoint")
	}
	return arn, nil
}

func subscriptionFilterQuota(r Reader, previous, next SubscriptionRecord) error {
	filtered := func(document string) bool { return document != "" && document != "{}" }
	if filtered(previous.FilterPolicy) || !filtered(next.FilterPolicy) {
		return nil
	}
	scope := next.Key.Topic.Scope
	scope.AccountID = next.Owner
	topicCount, err := r.FilterPolicyCount(scope, next.TopicID)
	if err != nil {
		return err
	}
	if topicCount >= 200 {
		return failure("FilterPolicyLimitExceeded", "The topic has reached its filter policy limit.", 403)
	}
	accountCount, err := r.FilterPolicyCount(scope, "")
	if err != nil {
		return err
	}
	if accountCount >= 10000 {
		return failure("FilterPolicyLimitExceeded", "The account has reached its filter policy limit.", 403)
	}
	return nil
}

func (s *Service) authorizeSubscriptionRole(ctx context.Context, sub SubscriptionRecord) error {
	if sub.SubscriptionRoleARN == "" {
		return failure("InvalidParameter", "Delivery protocol firehose can only be subscribed with subscription role arn")
	}
	if !validRoleARN(sub.Key.Topic.Scope, sub.SubscriptionRoleARN) {
		return failure("InvalidParameter", "SubscriptionRoleArn is not a valid role to be assumed by SNS")
	}
	if err := s.authorizeRequest(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: sub.SubscriptionRoleARN, Context: map[string][]string{"iam:PassedToService": {"sns.amazonaws.com"}, "iam:AssociatedResourceArn": {sub.Key.Topic.ARN()}}}); err != nil {
		return err
	}
	if s.roles == nil {
		return unsupported("SNS subscription role authority is not configured.")
	}
	if rejected := s.roles.ValidateSubscriptionRole(ctx, sub.Key.Topic, sub.SubscriptionRoleARN); rejected != nil {
		return rejected
	}
	return nil
}
