package sns

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func httpSubscription(protocol string) bool { return protocol == "http" || protocol == "https" }

const confirmationLifetime = 48 * time.Hour

func confirmationToken() string {
	var token [32]byte
	_, _ = rand.Read(token[:])
	return hex.EncodeToString(token[:])
}

// Anonymous confirmation is authorized by possession of the endpoint's token,
// not the resource owner's identity. Signed requests retain the gateway scope.
func confirmationContext(ctx context.Context, resource string) context.Context {
	metadata := awsctx.FromContext(ctx)
	if metadata.PrincipalARN != "" {
		return ctx
	}
	parts := strings.Split(resource, ":")
	if len(parts) >= 6 && parts[0] == "arn" && parts[2] == "sns" {
		metadata.Partition, metadata.Region = parts[1], parts[3]
		ctx = awsctx.WithMetadata(ctx, metadata)
	}
	return ctx
}

func (s *Service) stageConfirmation(tx Transaction, sub *SubscriptionRecord, topic TopicRecord, signer *rsa.PrivateKey, keyID, kind string) error {
	if signer == nil || s.delivery == nil {
		return unsupported("Subscription confirmation requires endpoint delivery and PublicEndpoint.")
	}
	now := s.clock.Now()
	token := confirmationToken()
	expires := now.Add(confirmationLifetime)
	// TODO: Comeback calibrate native pending/deleted subscription cleanup timing.
	if sub.State != "" {
		sub.DeletionDue = &expires
	}
	subscribeURL := s.publicEndpoint + "/?Action=ConfirmSubscription&TopicArn=" + url.QueryEscape(sub.Key.Topic.ARN()) + "&Token=" + url.QueryEscape(token)
	body := "You have chosen to subscribe to the topic " + sub.Key.Topic.ARN() + ".\nTo confirm the subscription, visit the SubscribeURL included in this message."
	if kind == "UnsubscribeConfirmation" {
		body = "You have chosen to deactivate subscription " + sub.Key.ARN() + ".\nTo reactivate the subscription, visit the SubscribeURL included in this message."
	}
	message := MessageRecord{Key: MessageKey{ID: identifier()}, Topic: sub.Key.Topic, Body: body, Published: now, Type: kind, Token: token, SubscribeURL: subscribeURL, SignatureVersion: topic.SignatureVersion}
	if message.SignatureVersion == "" {
		message.SignatureVersion = "1"
	}
	if strings.HasSuffix(sub.Endpoint, ".fifo") {
		message.MessageGroupID, message.MessageDeduplicationID = "Subscription", message.Key.ID
	}
	if err := signNotification(&message, signer, keyID); err != nil {
		return err
	}
	if err := tx.PutSubscription(*sub); err != nil {
		return err
	}
	if err := tx.DeleteExpiredConfirmations(now); err != nil {
		return err
	}
	if err := tx.PutConfirmation(ConfirmationRecord{Token: token, Subscription: sub.Key, Expires: expires}); err != nil {
		return err
	}
	if err := tx.PutMessage(message); err != nil {
		return err
	}
	return tx.PutDelivery(DeliveryRecord{ID: identifier(), Message: message.Key, Subscription: sub.Key, Due: now, Version: 1})
}

func (s *Service) confirmSubscription(ctx context.Context, in *api.ConfirmSubscriptionInput) (out *api.ConfirmSubscriptionOutput, rejected *awswire.Error) {
	ctx = confirmationContext(ctx, value(in.TopicArn))
	defer finishCall(s, ctx, "ConfirmSubscription", in, &out, &rejected, false)
	key, wire := topicKey(ctx, value(in.TopicArn))
	if wire != nil {
		return nil, wire
	}
	authenticate := value(in.AuthenticateOnUnsubscribe)
	if authenticate != "" && authenticate != "true" && authenticate != "false" {
		return nil, failure("InvalidParameter", "Invalid parameter: AuthenticateOnUnsubscribe")
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		token, err := tx.Confirmation(value(in.Token))
		if errors.Is(err, ErrNotFound) || err == nil && (token.Subscription.Topic.Partition != key.Partition || token.Subscription.Topic.Region != key.Region || !token.Expires.After(s.clock.Now())) {
			return failure("InvalidParameter", "Invalid parameter: Token")
		}
		if err != nil {
			return err
		}
		sub, err := tx.Subscription(token.Subscription)
		if errors.Is(err, ErrNotFound) {
			return failure("NotFound", "Subscription does not exist", 404)
		}
		if err != nil {
			return err
		}
		topic, err := tx.Topic(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		caller := awsctx.FromContext(ctx)
		if caller.PrincipalARN != "" {
			conditions := make(map[string][]string, len(topic.Tags))
			for tag, value := range topic.Tags {
				conditions["aws:ResourceTag/"+tag] = []string{value}
			}
			// AWS authorizes the requested TopicArn. Token possession supplies
			// resource consent and independently identifies the registration,
			// even when the requested topic differs or no longer exists.
			if err := s.authorizeRequest(tx.Context(), authorization.Request{
				Action: "sns:ConfirmSubscription", ResourceARN: key.ARN(),
				ResourceAccountGrant: true, Context: conditions,
				ResourcePolicies: []authorization.BoundPolicy{topic.Policy},
			}); err != nil {
				return err
			}
		}
		if authenticate == "true" && sub.State == "" && sub.AuthenticateOnUnsubscribe {
			return failure("AuthorizationError", "Subscription already confirmed", 403)
		}
		if authenticate == "true" && (caller.PrincipalARN == "" || caller.AccountID != sub.Owner) {
			return failure("AuthorizationError", "To disallow anonymous unsubscription, subscriber and confirmer IDs must match", 403)
		}
		currentTopic := topic.ID == sub.TopicID
		if sub.Key.Topic != key {
			original, err := tx.Topic(sub.Key.Topic)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			currentTopic = original.ID == sub.TopicID
		}
		if sub.State == "pending" && !currentTopic {
			return failure("NotFound", "Topic does not exist", 404)
		}
		if currentTopic && (sub.State != "" || authenticate == "true") {
			sub.State, sub.DeletionDue = "", nil
			sub.ConfirmationAuthenticated = authenticate == "true"
			sub.AuthenticateOnUnsubscribe = authenticate == "true"
			sub.Version++
			if err := tx.PutSubscription(sub); err != nil {
				return err
			}
		}
		out = &api.ConfirmSubscriptionOutput{SubscriptionArn: str[api.SubscriptionARN](sub.Key.ARN())}
		return s.recordCall(tx.Context(), "ConfirmSubscription", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}
