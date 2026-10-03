package integrations

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	api "stackd/internal/awsapi/sns"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/sns"
)

// SNSPublisher admits a service-produced message through SNS's ordinary policy,
// publication and retained fanout boundary. Nil error means durable acceptance.
type SNSPublisher interface {
	Publish(context.Context, *api.PublishInput) (*api.PublishOutput, *awswire.Error)
}

// SNSSubscriptions delivers SNS-owned native projections through destination
// commands. SNS supplies the source principal and causal context; destinations
// enforce their current policies and own post-acceptance execution.
type SNSSubscriptions struct {
	SQS      SQSSender
	Lambda   LambdaInvoker
	HTTP     *SNSHTTP
	Firehose *SNSFirehose
}

func (a SNSSubscriptions) Send(ctx context.Context, protocol, endpoint string, message sns.DeliveryMessage) sns.DeliveryResult {
	switch protocol {
	case "sqs":
		input := &sqsapi.SendMessageInput{MessageBody: (*sqsapi.String)(&message.Body), MessageAttributes: sqsMessageAttributes(message.Attributes)}
		if message.MessageGroupID != "" {
			input.MessageGroupId = (*sqsapi.String)(&message.MessageGroupID)
		}
		if message.MessageDeduplicationID != "" {
			input.MessageDeduplicationId = (*sqsapi.String)(&message.MessageDeduplicationID)
		}
		metadata, rejected := snsDestinationMetadata(ctx, endpoint)
		if rejected != nil {
			return snsDeliveryError(rejected, message.CaptureFeedback)
		}
		metadata.RequestID = uuid.NewString()
		if metadata.TraceHeader != "" {
			dataType, trace := sqsapi.String("String"), sqsapi.String(metadata.TraceHeader)
			input.MessageSystemAttributes = sqsapi.MessageBodySystemAttributeMap{
				"AWSTraceHeader": {DataType: &dataType, StringValue: &trace},
			}
		}
		out, rejected := a.SQS.SendToQueue(awsctx.WithMetadata(ctx, metadata), endpoint, input)
		result := sns.DeliveryResult{Error: rejected, StatusCode: 200}
		queueUnavailable := false
		if rejected != nil {
			result.StatusCode = rejected.StatusCode
			switch rejected.Code {
			case "AccessDenied", "AccessDeniedException", "AWS.SimpleQueueService.NonExistentQueue":
				queueUnavailable = true
				result.StatusCode = 400
			}
		}
		if message.CaptureFeedback {
			response := struct {
				ErrorCode    string         `json:"ErrorCode,omitempty"`
				ErrorMessage string         `json:"ErrorMessage,omitempty"`
				RequestID    string         `json:"sqsRequestId"`
				MessageID    *sqsapi.String `json:"sqsMessageId,omitempty"`
			}{RequestID: metadata.RequestID}
			if rejected == nil {
				response.MessageID = out.MessageId
			} else {
				response.ErrorCode, response.ErrorMessage = rejected.Code, rejected.Message
				if queueUnavailable {
					response.ErrorCode = "AWS.SimpleQueueService.NonExistentQueue"
					response.ErrorMessage = "The specified queue does not exist or you do not have access to it."
					response.RequestID = "Unrecoverable"
				}
			}
			encoded, _ := json.Marshal(response)
			result.ProviderResponse = string(encoded)
		}
		return result
	case "lambda":
		metadata, rejected := snsDestinationMetadata(ctx, endpoint)
		if rejected != nil {
			return snsDeliveryError(rejected, message.CaptureFeedback)
		}
		requestID, rejected := a.Lambda.InvokeEvent(awsctx.WithMetadata(ctx, metadata), endpoint, []byte(message.Body), "")
		result := sns.DeliveryResult{Error: rejected, StatusCode: 202}
		if rejected != nil {
			result.StatusCode = rejected.StatusCode
		}
		if message.CaptureFeedback {
			response := struct {
				ErrorCode    string `json:"ErrorCode,omitempty"`
				ErrorMessage string `json:"ErrorMessage,omitempty"`
				RequestID    string `json:"lambdaRequestId,omitempty"`
			}{RequestID: requestID}
			if rejected != nil {
				response.ErrorCode, response.ErrorMessage = rejected.Code, rejected.Message
				if rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" {
					response.ErrorCode = "AccessDeniedException"
				}
				if rejected.StatusCode >= 400 && rejected.StatusCode < 500 && rejected.StatusCode != 429 {
					response.RequestID = "Unrecoverable"
				}
			}
			encoded, _ := json.Marshal(response)
			result.ProviderResponse = string(encoded)
		}
		return result
	case "http", "https":
		return a.HTTP.Send(ctx, endpoint, message)
	case "firehose":
		return a.Firehose.Send(ctx, message.SubscriptionRoleARN, endpoint, message)
	default:
		return snsDeliveryError(&awswire.Error{Code: "NotImplementedException", Message: "Unsupported SNS delivery protocol: " + protocol, StatusCode: 501}, message.CaptureFeedback)
	}
}

// SNS retains the source topic's account and identity while the destination owns
// the request Region. Opt-in destinations recognize the generic service identity
// and their regional alias; opt-in sources reaching default Regions use only the
// source's regional identity.
func snsDestinationMetadata(ctx context.Context, endpoint string) (awsctx.Metadata, *awswire.Error) {
	target, err := arn.Parse(endpoint)
	if err != nil {
		return awsctx.Metadata{}, &awswire.Error{Code: "InvalidParameter", Message: "Invalid subscription endpoint ARN.", StatusCode: 400}
	}
	metadata := awsctx.FromContext(ctx)
	if metadata.Partition == "aws" {
		if awscatalog.CommercialRegionRequiresOptIn(target.Region) {
			metadata.ServicePrincipal.Aliases = []string{"sns." + target.Region + ".amazonaws.com"}
		} else if metadata.Region != target.Region && awscatalog.CommercialRegionRequiresOptIn(metadata.Region) {
			metadata.ServicePrincipal.Name = "sns." + metadata.Region + ".amazonaws.com"
		}
	}
	metadata.Region = target.Region
	return metadata, nil
}

func snsDeliveryError(rejected *awswire.Error, capture bool) sns.DeliveryResult {
	result := sns.DeliveryResult{Error: rejected, StatusCode: rejected.StatusCode}
	if capture {
		result.ProviderResponse = rejected.Message
	}
	return result
}

// sqsMessageAttributes preserves the shared SNS/SQS attribute wire values.
func sqsMessageAttributes(attributes api.MessageAttributeMap) sqsapi.MessageBodyAttributeMap {
	if len(attributes) == 0 {
		return nil
	}
	result := make(sqsapi.MessageBodyAttributeMap, len(attributes))
	for name, value := range attributes {
		result[sqsapi.String(name)] = sqsapi.MessageAttributeValue{DataType: (*sqsapi.String)(value.DataType), StringValue: (*sqsapi.String)(value.StringValue), BinaryValue: sqsapi.Binary(value.BinaryValue)}
	}
	return result
}
