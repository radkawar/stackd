package s3

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// NotificationDestinations owns external destination commands. Validation sends
// the supplied test event to SNS/SQS and checks Lambda invocation permission;
// Send submits an accepted object event. Neither method runs in an S3 transaction.
type NotificationDestinations interface {
	Validate(context.Context, NotificationDelivery) (string, *awswire.Error)
	Send(context.Context, NotificationDelivery) *awswire.Error
}

// NativeObjectEvents joins S3's transaction to the configured default event bus.
// Recipient execution remains outside that transaction.
type NativeObjectEvents interface {
	PublishObjectEvent(context.Context, BucketRecord, time.Time, string, string, string) error
}

// Notification configuration becomes visible to reads before producers adopt
// it. One minute is a local deterministic propagation interval, not an AWS SLA.
const notificationPropagation = time.Minute

type notificationPutResponse struct {
	output    api.PutBucketNotificationConfigurationOutput
	messageID string
}

func (r *notificationPutResponse) responseWithHeaders(headers http.Header) any {
	if r.messageID != "" {
		headers.Set("x-amz-sns-test-message-id", r.messageID)
	}
	return r.modeledOutput()
}

func (r *notificationPutResponse) modeledOutput() any { return &r.output }

func (s *Service) getBucketNotificationConfiguration(ctx context.Context, in *api.GetBucketNotificationConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketNotificationConfiguration", value(in.Bucket), "", "notification")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		bucket, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if rejected := s.authorize(tx.Context(), c, bucket, "GetBucketNotification", "", nil); rejected != nil {
			return rejected
		}
		state, err := tx.NotificationState(bucket.Key)
		if errors.Is(err, ErrNotFound) {
			return response.prepare(c, &api.GetBucketNotificationConfigurationOutput{})
		}
		if err != nil {
			return err
		}
		return response.prepare(c, notificationConfigurationOutput(state.Desired))
	})
	return response, wire
}

func (s *Service) putBucketNotificationConfiguration(ctx context.Context, in *api.PutBucketNotificationConfigurationInput) (*notificationPutResponse, *awswire.Error) {
	c := call(ctx, "PutBucketNotificationConfiguration", value(in.Bucket), "")
	notificationParameters(c, in.NotificationConfiguration)
	c.additional = map[string]any{"httpStatusCode": 200}
	out := &notificationPutResponse{}
	var admitted BucketRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		admitted, err = s.bucket(r, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if rejected := s.authorize(r.Context(), c, admitted, "PutBucketNotification", "", nil); rejected != nil {
			return rejected
		}
		return nil
	})
	if err != nil {
		return out, s.complete(ctx, c, err)
	}
	configuration, rejected := parseNotificationConfiguration(in.NotificationConfiguration, admitted)
	if rejected != nil {
		return out, s.complete(ctx, c, rejected)
	}
	if configuration.EventBridge && s.objectEvents == nil {
		return out, s.complete(ctx, c, unsupported("Native EventBridge publication is not configured."))
	}
	if len(configuration.Rules) != 0 && (in.SkipDestinationValidation == nil || !bool(*in.SkipDestinationValidation)) {
		if s.notifications == nil {
			return out, s.complete(ctx, c, unsupported("Notification destination commands are not configured."))
		}
		payload, err := notificationTestEvent(awsctx.FromContext(ctx), admitted, s.clock.Now())
		c.eventID = uuid.NewString()
		if err != nil {
			return out, s.complete(ctx, c, err)
		}
		// Native failed mixed replacements can still publish test messages to
		// valid destinations. Do not roll back or stop those independent calls.
		var validationFailure *awswire.Error
		for _, rule := range configuration.Rules {
			delivery := notificationDelivery(ctx, c, admitted, rule, payload)
			messageID, wire := s.notifications.Validate(ctx, delivery)
			if wire != nil {
				if validationFailure == nil {
					validationFailure = wire
				}
				continue
			}
			if len(configuration.Rules) == 1 && rule.Protocol == NotificationSNS && len(rule.Events) == 1 && rule.Events[0] == "s3:ReducedRedundancyLostObject" {
				out.messageID = messageID
			}
		}
		if validationFailure != nil {
			return out, s.complete(ctx, c, invalid("Unable to validate the following destination configurations"))
		}
	}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		bucket, err := s.bucket(tx, c, admitted.AccountID)
		if err != nil {
			return err
		}
		state, err := tx.NotificationState(bucket.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		state.Bucket = bucket.Key
		state.Desired = configuration
		at := s.clock.Now().Add(notificationPropagation)
		state.ApplyAt = &at
		state.Version++
		return tx.PutNotificationState(state)
	})
	return out, wire
}

func notificationDelivery(ctx context.Context, c *apiCall, bucket BucketRecord, rule NotificationRule, payload string) NotificationDelivery {
	return NotificationDelivery{
		Bucket: bucket.Key, AccountID: bucket.AccountID, Region: bucket.Region,
		Protocol: rule.Protocol, DestinationARN: rule.DestinationARN, Payload: payload,
		RequestID: awsctx.FromContext(ctx).RequestID, ParentEventID: c.eventID,
	}
}
