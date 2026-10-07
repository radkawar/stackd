package sns

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var subscriptionIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var subscriptionQueueNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.fifo)?$`)
var subscriptionFirehoseNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var subscriptionFunctionNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var subscriptionQualifierPattern = regexp.MustCompile(`^(\$LATEST|[A-Za-z0-9_-]{1,128})$`)

func (s *Service) registerSubscriptions() {
	register(s, "Subscribe", s.subscribe)
	register(s, "ConfirmSubscription", s.confirmSubscription)
	register(s, "Unsubscribe", s.unsubscribe)
	register(s, "GetSubscriptionAttributes", s.getSubscriptionAttributes)
	register(s, "SetSubscriptionAttributes", s.setSubscriptionAttributes)
	register(s, "ListSubscriptions", s.listSubscriptions)
	register(s, "ListSubscriptionsByTopic", s.listSubscriptionsByTopic)
}

func subscriptionKey(ctx context.Context, arn string) (SubscriptionKey, *awswire.Error) {
	separator := strings.LastIndexByte(arn, ':')
	if separator < 0 || !subscriptionIDPattern.MatchString(arn[separator+1:]) {
		return SubscriptionKey{}, failure("InvalidParameter", "Invalid parameter: SubscriptionArn")
	}
	topic, wire := topicKey(ctx, arn[:separator])
	if wire != nil {
		return SubscriptionKey{}, failure("InvalidParameter", "Invalid parameter: SubscriptionArn")
	}
	return SubscriptionKey{Topic: topic, ID: arn[separator+1:]}, nil
}

// Endpoint admission checks ARN syntax, not whether the destination exists or
// grants delivery permission. Those checks belong to the real delivery adapter.
func subscriptionEndpoint(topic TopicKey, protocol, endpoint string) (string, *awswire.Error) {
	if strings.HasSuffix(topic.Name, ".fifo") && protocol != "sqs" {
		return "", failure("InvalidParameter", "FIFO topics support only SQS subscriptions.")
	}
	switch protocol {
	case "sqs", "lambda", "firehose":
	case "http", "https":
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != protocol || u.Hostname() == "" || u.Opaque != "" || u.User != nil && protocol != "https" {
			return "", failure("InvalidParameter", "Invalid parameter: Endpoint")
		}
		return "", nil
	case "email", "email-json", "sms", "application":
		// TODO: Comeback — SMTP is deferred; mobile/SMS need real delivery adapters.
		return "", unsupported("Subscription protocol " + protocol + " is not implemented.")
	default:
		return "", failure("InvalidParameter", "Invalid parameter: Protocol")
	}
	parts := strings.Split(endpoint, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[1] != topic.Partition || parts[2] != protocol || parts[3] == "" || !accountPattern.MatchString(parts[4]) {
		return "", failure("InvalidParameter", "Invalid parameter: Endpoint")
	}
	if protocol != "firehose" && awscatalog.RegionPartition(parts[3]) != topic.Partition {
		return "", failure("InvalidParameter", "Invalid parameter: Endpoint")
	}
	if protocol == "sqs" {
		if len(parts) == 6 && strings.HasSuffix(parts[5], ".fifo") && !strings.HasSuffix(topic.Name, ".fifo") {
			return "", failure("InvalidParameter", "FIFO SQS queues cannot be subscribed to standard SNS topics.")
		}
		if len(parts) != 6 || len(parts[5]) > 80 || !subscriptionQueueNamePattern.MatchString(parts[5]) {
			return "", failure("InvalidParameter", "Invalid parameter: Endpoint")
		}
	} else if protocol == "firehose" {
		if len(parts) != 6 || !strings.HasPrefix(parts[5], "deliverystream/") || !subscriptionFirehoseNamePattern.MatchString(strings.TrimPrefix(parts[5], "deliverystream/")) {
			return "", failure("InvalidParameter", "Invalid parameter: Endpoint")
		}
	} else if (len(parts) != 7 && len(parts) != 8) || parts[5] != "function" || !subscriptionFunctionNamePattern.MatchString(parts[6]) || (len(parts) == 8 && !subscriptionQualifierPattern.MatchString(parts[7])) {
		return "", failure("InvalidParameter", "Invalid parameter: Endpoint")
	}
	return parts[4], nil
}

func (s *Service) subscribe(ctx context.Context, in *api.SubscribeInput) (out *api.SubscribeOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "Subscribe", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.TopicArn))
	if wire != nil {
		return nil, wire
	}
	protocol, endpoint := value(in.Protocol), value(in.Endpoint)
	endpointOwner, endpointErr := subscriptionEndpoint(key, protocol, endpoint)
	caller := awsctx.FromContext(ctx)
	endpointConfirmation := protocol == "sqs" || protocol == "lambda"
	var signer *rsa.PrivateKey
	var signingID string
	if (httpSubscription(protocol) || endpointConfirmation) && endpointErr == nil {
		var err error
		signer, signingID, err = s.publicationSigner(ctx)
		if err != nil {
			return nil, wireError(err)
		}
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if endpointErr != nil {
			return endpointErr
		}
		conditions := map[string][]string{"sns:Protocol": {protocol}, "sns:Endpoint": {endpoint}}
		if err := s.authorize(tx, "Subscribe", key.ARN(), topic.Tags, conditions, topic.Policy); err != nil {
			return err
		}
		if err := checkCloudFormationTopicClaim(tx.Context(), topic); err != nil {
			return err
		}
		if protocol == "firehose" && endpointOwner != caller.AccountID {
			return failure("AuthorizationError", "The account "+caller.AccountID+" is not the owner of the endpoint "+endpoint, 403)
		}
		previous, err := tx.SubscriptionByEndpoint(topic.ID, protocol, endpoint)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		needsConfirmation := httpSubscription(protocol) || endpointConfirmation && endpointOwner != caller.AccountID
		sub := previous
		if !exists {
			principal := caller.PrincipalARN
			if strings.Contains(caller.PrincipalARN, ":assumed-role/") {
				principal = caller.IssuerARN
			}
			sub = SubscriptionRecord{Key: SubscriptionKey{Topic: key, ID: identifier()}, TopicID: topic.ID, Owner: caller.AccountID, PrincipalARN: principal, Protocol: protocol, Endpoint: endpoint, Created: s.clock.Now(), Version: 1}
			sub.ConfirmationAuthenticated = !needsConfirmation
			sub.AuthenticateOnUnsubscribe = !needsConfirmation
			if needsConfirmation {
				sub.State = "pending"
			}
		}
		if previous.State == "deleted" && httpSubscription(protocol) {
			sub.State = "pending"
			sub.Version++
		}
		if wire := s.applySubscriptionAttributes(tx, &sub, in.Attributes); wire != nil {
			return wire
		}
		if protocol == "firehose" {
			if err := s.authorizeSubscriptionRole(tx.Context(), sub); err != nil {
				return err
			}
		}
		if exists {
			if sub.RawMessageDelivery != previous.RawMessageDelivery || sub.FilterPolicy != previous.FilterPolicy || sub.FilterScope != previous.FilterScope || sub.RedriveARN != previous.RedriveARN || sub.SubscriptionRoleARN != previous.SubscriptionRoleARN || sub.DeliveryPolicy != previous.DeliveryPolicy {
				return failure("InvalidParameter", "Invalid parameter: Attributes Reason: Subscription already exists with different attributes")
			}
			if sub.Replay.Policy != previous.Replay.Policy {
				return failure("InvalidParameter", "Invalid parameter: Attributes Reason: Subscription already exists with different attributes")
			}
		} else {
			count, err := tx.SubscriptionCount(topic.ID)
			if err != nil {
				return err
			}
			if count >= 12500000 {
				return failure("SubscriptionLimitExceeded", "The topic has reached its subscription limit.", 403)
			}
			if err := subscriptionFilterQuota(tx, previous, sub); err != nil {
				return err
			}
		}
		if sub.State == "pending" || endpointConfirmation && needsConfirmation {
			if err := s.stageConfirmation(tx, &sub, topic, signer, signingID, "SubscriptionConfirmation"); err != nil {
				return err
			}
		} else if !exists {
			if err := tx.PutSubscription(sub); err != nil {
				return err
			}
		}
		arn := sub.Key.ARN()
		if sub.State == "pending" && (in.ReturnSubscriptionArn == nil || !*in.ReturnSubscriptionArn) {
			arn = "pending confirmation"
		}
		out = &api.SubscribeOutput{SubscriptionArn: str[api.SubscriptionARN](arn)}
		return s.recordCall(tx.Context(), "Subscribe", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

// SNS IAM subscription actions use the topic ARN, not the subscription ARN.
// The service-owned owner relationship supplies only the resource-account side
// of cross-account access; the shared evaluator still enforces every IAM limit.
func (s *Service) authorizeSubscription(r Reader, action string, sub SubscriptionRecord) error {
	caller := scopeFor(r.Context()).AccountID
	if caller != sub.Owner && !(action == "Unsubscribe" && (caller == sub.Key.Topic.AccountID || !sub.AuthenticateOnUnsubscribe)) {
		return failure("AuthorizationError", "Only the subscription owner may perform this action.", 403)
	}
	topic, err := r.Topic(sub.Key.Topic)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := checkCloudFormationTopicClaim(r.Context(), topic); err != nil {
		return err
	}
	if _, managed := r.Context().Value(cloudFormationTopicContextKey{}).(CloudFormationTopicClaim); managed && sub.TopicID != topic.ID {
		return failure("InvalidParameter", "Subscription belongs to another topic incarnation")
	}
	conditions := make(map[string][]string, len(topic.Tags))
	for key, v := range topic.Tags {
		conditions["aws:ResourceTag/"+key] = []string{v}
	}
	return s.authorizeRequest(r.Context(), authorization.Request{
		Action: "sns:" + action, ResourceARN: sub.Key.Topic.ARN(),
		ResourceAccountGrant: caller != sub.Key.Topic.AccountID && (caller == sub.Owner || action == "Unsubscribe" && !sub.AuthenticateOnUnsubscribe),
		Context:              conditions, ResourcePolicies: []authorization.BoundPolicy{topic.Policy},
	})
}

func (s *Service) unsubscribe(ctx context.Context, in *api.UnsubscribeInput) (out *api.UnsubscribeOutput, rejected *awswire.Error) {
	ctx = confirmationContext(ctx, value(in.SubscriptionArn))
	defer finishCall(s, ctx, "Unsubscribe", in, &out, &rejected, false)
	key, wire := subscriptionKey(ctx, value(in.SubscriptionArn))
	if wire != nil {
		return nil, wire
	}
	signer, signingID, err := s.publicationSigner(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		sub, err := tx.Subscription(key)
		caller := awsctx.FromContext(ctx)
		anonymous := caller.PrincipalARN == ""
		if errors.Is(err, ErrNotFound) {
			if !anonymous {
				if err := s.authorizeRequest(tx.Context(), authorization.Request{Action: "sns:Unsubscribe", ResourceARN: key.Topic.ARN(), ResourceAccountGrant: true}); err != nil {
					return err
				}
			}
		} else {
			if err != nil {
				return err
			}
			if sub.State == "pending" {
				return failure("InvalidParameter", "Invalid parameter: SubscriptionArn Reason: Cannot unsubscribe a subscription that is pending confirmation")
			}
			if anonymous {
				if !httpSubscription(sub.Protocol) || sub.AuthenticateOnUnsubscribe {
					return failure("AuthorizationError", "This subscription requires authentication for deletion.", 403)
				}
			} else if err := s.authorizeSubscription(tx, "Unsubscribe", sub); err != nil {
				return err
			}
			if sub.State == "" && (anonymous || caller.AccountID != sub.Owner) {
				if err := tx.DeleteSubscriptionNotifications(key); err != nil {
					return err
				}
				sub.State = "deleted"
				sub.Version++
				if sub.Protocol == "lambda" || sub.Protocol == "firehose" {
					due := s.clock.Now().Add(confirmationLifetime)
					sub.DeletionDue = &due
					if err := tx.PutSubscription(sub); err != nil {
						return err
					}
				} else {
					topic, err := tx.Topic(key.Topic)
					if err != nil {
						return err
					}
					if err := s.stageConfirmation(tx, &sub, topic, signer, signingID, "UnsubscribeConfirmation"); err != nil {
						return err
					}
				}
			} else if sub.State != "deleted" || !anonymous && caller.AccountID == sub.Owner {
				if err := tx.DeleteSubscription(key); err != nil {
					return err
				}
			}
		}
		out = &api.UnsubscribeOutput{}
		return s.recordCall(tx.Context(), "Unsubscribe", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func decodeSubscriptionCursor(ctx context.Context, token *api.NextToken, collection string) (SubscriptionKey, *awswire.Error) {
	if token == nil {
		return SubscriptionKey{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value(token))
	var cursor pageCursor
	if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Collection != collection {
		return SubscriptionKey{}, failure("InvalidParameter", "Invalid parameter: NextToken")
	}
	key, wire := subscriptionKey(ctx, cursor.After)
	if wire != nil {
		return SubscriptionKey{}, failure("InvalidParameter", "Invalid parameter: NextToken")
	}
	return key, nil
}

func subscriptionList(rows []SubscriptionRecord) api.SubscriptionsList {
	out := make(api.SubscriptionsList, 0, len(rows))
	for _, sub := range rows {
		arn := sub.Key.ARN()
		if sub.State == "pending" {
			arn = "PendingConfirmation"
		}
		if sub.State == "deleted" {
			arn = "Deleted"
		}
		endpoint := displaySubscriptionEndpoint(sub.Protocol, sub.Endpoint)
		out = append(out, api.Subscription{SubscriptionArn: str[api.SubscriptionARN](arn), TopicArn: str[api.TopicARN](sub.Key.Topic.ARN()), Owner: str[api.Account](sub.Owner), Protocol: str[api.Protocol](sub.Protocol), Endpoint: str[api.Endpoint2](endpoint)})
	}
	return out
}

func displaySubscriptionEndpoint(protocol, endpoint string) string {
	if protocol == "https" {
		if parsed, err := url.Parse(endpoint); err == nil && parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword {
				parsed.User = url.UserPassword(parsed.User.Username(), "****")
				endpoint = parsed.String()
			}
		}
	}
	return endpoint
}

func (s *Service) listSubscriptions(ctx context.Context, in *api.ListSubscriptionsInput) (out *api.ListSubscriptionsOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListSubscriptions", in, &out, &rejected, false)
	scope := scopeFor(ctx)
	collection := (TopicKey{Scope: scope}).ARN() + "/ListSubscriptions"
	cursor, wire := decodeSubscriptionCursor(ctx, in.NextToken, collection)
	if wire != nil {
		return nil, wire
	}
	after := ""
	if in.NextToken != nil {
		after = cursor.ARN()
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "ListSubscriptions", "*", nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		rows, err := tx.SubscriptionsByOwner(OwnerSubscriptionQuery{Scope: scope, AfterARN: after, Limit: 101})
		if err != nil {
			return err
		}
		out = &api.ListSubscriptionsOutput{}
		if len(rows) > 100 {
			rows = rows[:100]
			out.NextToken = encodeTopicCursor(collection, rows[99].Key.ARN())
		}
		out.Subscriptions = subscriptionList(rows)
		return s.recordCall(tx.Context(), "ListSubscriptions", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) listSubscriptionsByTopic(ctx context.Context, in *api.ListSubscriptionsByTopicInput) (out *api.ListSubscriptionsByTopicOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListSubscriptionsByTopic", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.TopicArn))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		topic, err := tx.Topic(key)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "ListSubscriptionsByTopic", key.ARN(), topic.Tags, nil, topic.Policy); err != nil {
			return err
		}
		if err := checkCloudFormationTopicClaim(tx.Context(), topic); err != nil {
			return err
		}
		collection := key.ARN() + "/ListSubscriptionsByTopic/" + scopeFor(ctx).AccountID + "/" + topic.ID
		cursor, wire := decodeSubscriptionCursor(ctx, in.NextToken, collection)
		if wire != nil {
			return wire
		}
		if in.NextToken != nil && cursor.Topic != key {
			return failure("InvalidParameter", "Invalid parameter: NextToken")
		}
		rows, err := tx.SubscriptionsByTopic(TopicSubscriptionQuery{Topic: key, TopicID: topic.ID, After: cursor.ID, Limit: 101})
		if err != nil {
			return err
		}
		out = &api.ListSubscriptionsByTopicOutput{}
		if len(rows) > 100 {
			rows = rows[:100]
			out.NextToken = encodeTopicCursor(collection, rows[99].Key.ARN())
		}
		out.Subscriptions = subscriptionList(rows)
		return s.recordCall(tx.Context(), "ListSubscriptionsByTopic", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
