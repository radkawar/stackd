package integrations

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
)

// EventBridgeLogsAPI is the authorized command boundary for log group targets.
// EventBridge creates streams, but never creates the configured destination group.
type EventBridgeLogsAPI interface {
	CreateLogStream(context.Context, *api.CreateLogStreamRequest) (*api.CreateLogStreamOutput, *awswire.Error)
	PutLogEvents(context.Context, *api.PutLogEventsRequest) (*api.PutLogEventsResponse, *awswire.Error)
}

func (a EventBridgeTargets) sendLogs(ctx context.Context, request eventbridge.DeliveryRequest, target arn.ARN, body string) *awswire.Error {
	groupName, ok := strings.CutPrefix(target.Resource, "log-group:")
	if !ok || groupName == "" || strings.Contains(groupName, ":") {
		return &awswire.Error{Code: "InvalidAddress", Message: "CloudWatch Logs targets require a log group ARN.", StatusCode: 400}
	}
	metadata := awsctx.FromContext(ctx)
	if target.AccountID != metadata.AccountID {
		// TODO: Comeback establish cross-account Logs target delivery and separate destination routing from the trusted source account.
		return &awswire.Error{Code: "NotImplementedException", Message: "Cross-account CloudWatch Logs target delivery is not implemented.", StatusCode: 501}
	}
	if a.Logs == nil {
		return &awswire.Error{Code: "InternalException", Message: "No CloudWatch Logs delivery adapter is configured.", StatusCode: 500}
	}
	event, wire := eventBridgeLogEvent(request, body)
	if wire != nil {
		return wire
	}
	// Native captures use UUID-shaped streams. Deriving our stream from retained
	// delivery identity keeps retries stable, without claiming AWS's allocation
	// algorithm or batching/stream reuse boundaries.
	namespace := uuid.NewMD5(uuid.NameSpaceURL, []byte(request.Delivery.RuleARN))
	streamName := uuid.NewMD5(namespace, []byte(request.Delivery.TargetARN+"\x00"+request.Event.ID)).String()
	group, stream := new(api.LogGroupName(groupName)), new(api.LogStreamName(streamName))
	command := func() context.Context {
		metadata.RequestID = uuid.NewString()
		return awsctx.WithMetadata(ctx, metadata)
	}
	if _, wire := a.Logs.CreateLogStream(command(), &api.CreateLogStreamRequest{LogGroupName: group, LogStreamName: stream}); wire != nil && wire.Code != "ResourceAlreadyExistsException" {
		return eventBridgeLogsError(wire, groupName)
	}
	out, wire := a.Logs.PutLogEvents(command(), &api.PutLogEventsRequest{LogGroupName: group, LogStreamName: stream, LogEvents: api.InputLogEvents{event}})
	if wire != nil {
		return eventBridgeLogsError(wire, groupName)
	}
	if out.RejectedLogEventsInfo != nil {
		// AWS's EventBridge diagnostic for timestamp rejection has not been captured.
		return &awswire.Error{Code: "InvalidParameterException", Message: "CloudWatch Logs rejected the event timestamp for " + groupName + ".", StatusCode: 400}
	}
	return nil
}

func eventBridgeLogEvent(request eventbridge.DeliveryRequest, body string) (api.InputLogEvent, *awswire.Error) {
	timestamp := request.Event.Time.UTC().Truncate(time.Second)
	message := body
	if request.Delivery.HasInput {
		var transformed struct {
			Timestamp *time.Time `json:"timestamp"`
			Message   *string    `json:"message"`
		}
		if err := json.Unmarshal([]byte(body), &transformed); err != nil || transformed.Timestamp == nil || transformed.Message == nil {
			// PutTargets admits templates missing these fields. Reject unusable
			// runtime output, rather than substituting the original event or time.
			// The native diagnostic for this delivery failure is not yet captured.
			return api.InputLogEvent{}, &awswire.Error{Code: "InvalidParameterException", Message: "CloudWatch Logs input transformation requires an RFC3339 timestamp and a string message.", StatusCode: 400}
		}
		timestamp, message = *transformed.Timestamp, *transformed.Message
	}
	return api.InputLogEvent{Timestamp: new(api.Timestamp(timestamp.UnixMilli())), Message: new(api.EventMessage(message))}, nil
}

func eventBridgeLogsError(wire *awswire.Error, group string) *awswire.Error {
	code := strings.ToLower(wire.Code)
	if strings.Contains(code, "accessdenied") || strings.Contains(code, "permission") {
		out := *wire
		out.Message = "Could not complete putLogEvents call for " + group + "."
		return &out
	}
	return wire
}
