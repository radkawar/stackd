package sns

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"hash/fnv"
	"log/slog"
	"stackd/internal/awswire"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
)

// FeedbackPublisher writes an observed delivery using the configured execution
// role, outside source transactions. Log failure cannot revoke target acceptance.
type FeedbackPublisher interface {
	WriteFeedback(context.Context, string, FeedbackRecord) *awswire.Error
}

type FeedbackRecord struct {
	Notification FeedbackNotification `json:"notification"`
	Delivery     FeedbackDelivery     `json:"delivery"`
	Status       string               `json:"status"`
}

type FeedbackNotification struct {
	MessageMD5Sum string `json:"messageMD5Sum,omitempty"`
	MessageID     string `json:"messageId"`
	TopicARN      string `json:"topicArn"`
	Timestamp     string `json:"timestamp"`
}

type FeedbackDelivery struct {
	DeliveryID       string `json:"deliveryId"`
	Destination      string `json:"destination"`
	ProviderResponse string `json:"providerResponse"`
	DwellTimeMillis  int64  `json:"dwellTimeMs"`
	StatusCode       int    `json:"statusCode"`
	Attempts         int    `json:"attempts,omitempty"`
	RedrivePolicy    string `json:"redrivePolicy,omitempty"`
}

var feedbackProtocols = [...]struct{ prefix, protocol string }{
	{"HTTP", "http"}, {"SQS", "sqs"}, {"Lambda", "lambda"}, {"Firehose", "firehose"},
}

func feedbackAttribute(name string) (protocol, attribute string) {
	for _, candidate := range feedbackProtocols {
		if suffix, ok := strings.CutPrefix(name, candidate.prefix); ok {
			switch suffix {
			case "SuccessFeedbackRoleArn", "FailureFeedbackRoleArn", "SuccessFeedbackSampleRate":
				return candidate.protocol, suffix
			}
		}
	}
	return "", ""
}

func (s *Service) setFeedbackAttribute(ctx context.Context, topic *TopicRecord, protocol, attribute, value string) error {
	setting := topic.Feedback[protocol]
	if attribute == "SuccessFeedbackSampleRate" {
		rate, err := strconv.Atoi(value)
		if err != nil || rate < 0 || rate > 100 {
			return failure("InvalidParameter", "Success feedback sample rate must be an integer between 0 and 100.")
		}
		setting.SuccessSampleRate, setting.SampleRateSet = rate, true
	} else {
		if value != "" {
			if !validRoleARN(topic.Key.Scope, value) {
				return failure("InvalidParameter", value+" is not a valid role to allow SNS to write to Cloudwatch Logs")
			}
			if err := s.authorizeRequest(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: value, Context: map[string][]string{"iam:PassedToService": {"sns.amazonaws.com"}, "iam:AssociatedResourceArn": {topic.Key.ARN()}}}); err != nil {
				return err
			}
			if s.roles == nil {
				return unsupported("SNS feedback role authority is not configured.")
			}
			if rejected := s.roles.ValidateFeedbackRole(ctx, topic.Key, value); rejected != nil {
				return rejected
			}
		}
		if attribute == "SuccessFeedbackRoleArn" {
			setting.SuccessRoleARN = value
		} else {
			setting.FailureRoleARN = value
		}
	}
	if setting == (FeedbackConfig{}) {
		delete(topic.Feedback, protocol)
		return nil
	}
	if topic.Feedback == nil {
		topic.Feedback = make(map[string]FeedbackConfig)
	}
	topic.Feedback[protocol] = setting
	return nil
}

func feedbackAttributes(topic TopicRecord, attributes api.TopicAttributesMap) {
	for _, candidate := range feedbackProtocols {
		setting, ok := topic.Feedback[candidate.protocol]
		if !ok {
			continue
		}
		if setting.SuccessRoleARN != "" {
			attributes[api.AttributeName(candidate.prefix+"SuccessFeedbackRoleArn")] = api.AttributeValue(setting.SuccessRoleARN)
		}
		if setting.FailureRoleARN != "" {
			attributes[api.AttributeName(candidate.prefix+"FailureFeedbackRoleArn")] = api.AttributeValue(setting.FailureRoleARN)
		}
		if setting.SampleRateSet {
			attributes[api.AttributeName(candidate.prefix+"SuccessFeedbackSampleRate")] = api.AttributeValue(strconv.Itoa(setting.SuccessSampleRate))
		}
	}
}

// Sampling is stable for one retained delivery, including after a restart.
func feedbackRoles(setting FeedbackConfig, deliveryID string) (success, failure string) {
	failure = setting.FailureRoleARN
	if setting.SuccessRoleARN == "" {
		return "", failure
	}
	// Role-only configuration logs successes without materializing the rate
	// attribute; an explicit rate selects the requested fraction instead.
	if !setting.SampleRateSet || setting.SuccessSampleRate == 100 {
		return setting.SuccessRoleARN, failure
	}
	if setting.SuccessSampleRate == 0 {
		return "", failure
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(deliveryID))
	if hash.Sum64()%100 < uint64(setting.SuccessSampleRate) {
		success = setting.SuccessRoleARN
	}
	return success, failure
}

func (s *Service) recordFeedback(ctx context.Context, roleARN string, message *MessageRecord, sub *SubscriptionRecord, attempts int, dwellTimeMillis int64, outcome DeliveryResult, success bool) {
	record := FeedbackRecord{
		Notification: FeedbackNotification{
			MessageID: message.Key.ID, TopicARN: message.Topic.ARN(),
			Timestamp: message.Published.UTC().Format("2006-01-02 15:04:05.000"),
		},
		Delivery: FeedbackDelivery{
			DeliveryID: awsctx.FromContext(ctx).RequestID, Destination: displaySubscriptionEndpoint(sub.Protocol, sub.Endpoint),
			ProviderResponse: outcome.ProviderResponse, StatusCode: outcome.StatusCode,
			DwellTimeMillis: dwellTimeMillis, Attempts: attempts,
		},
		Status: "FAILURE",
	}
	if success {
		record.Status = "SUCCESS"
	}
	if message.Type == "" {
		sum := md5.Sum([]byte(message.Body))
		record.Notification.MessageMD5Sum = hex.EncodeToString(sum[:])
		if sub.RedriveARN != "" {
			record.Delivery.RedrivePolicy = redrivePolicyJSON(sub.RedriveARN)
		}
	}
	if rejected := s.feedback.WriteFeedback(ctx, roleARN, record); rejected != nil {
		slog.WarnContext(ctx, "SNS delivery feedback failed", "topic", record.Notification.TopicARN, "role", roleARN, "error", rejected)
	}
}
