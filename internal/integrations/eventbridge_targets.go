// Package integrations adapts service delivery contracts to target commands.
package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	eventsapi "stackd/internal/awsapi/eventbridge"
	snsapi "stackd/internal/awsapi/sns"
	api "stackd/internal/awsapi/sqs"
	stepfunctionsapi "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
)

// SQSSender is the command boundary consumed by EventBridge target delivery.
type SQSSender interface {
	SendToQueue(context.Context, string, *api.SendMessageInput) (*api.SendMessageOutput, *awswire.Error)
}

// LambdaInvoker accepts asynchronous work through Lambda's authorization and queue.
type LambdaInvoker interface {
	InvokeEvent(context.Context, string, []byte, string) (string, *awswire.Error)
}

// StepFunctionsStarter admits executions through Step Functions' audited command.
type StepFunctionsStarter interface {
	StartExecution(context.Context, *stepfunctionsapi.StartExecutionInput) (*stepfunctionsapi.StartExecutionOutput, *awswire.Error)
}

// StepFunctionsCompletions consumes terminal events selected by managed rules.
type StepFunctionsCompletions interface {
	NotifyCompletion(context.Context, json.RawMessage) error
}

// EventBusForwarder accepts a retained event without inventing a client PutEvents.
type EventBusForwarder interface {
	ForwardToBus(context.Context, string, eventbridge.EventRecord) *awswire.Error
}

// APIDestinationInvoker owns authenticated HTTPS effects and response classification.
// Rule and Pipes adapters supply their current execution-role context.
type APIDestinationInvoker interface {
	InvokeAPIDestination(context.Context, string, *eventsapi.HttpParameters, string, io.Writer) *awswire.Error
}

// EventBridgeTargets owns destination command routing and execution identity.
type EventBridgeTargets struct {
	SQS                      SQSSender
	SNS                      SNSPublisher
	Lambda                   LambdaInvoker
	Logs                     EventBridgeLogsAPI
	Events                   EventBusForwarder
	APIDestinations          APIDestinationInvoker
	ECS                      ECSTaskRunner
	Kinesis                  KinesisRecordWriter
	Firehose                 FirehoseRecordWriter
	StepFunctions            StepFunctionsStarter
	StepFunctionsCompletions StepFunctionsCompletions
	CodePipeline             awscommands.CommandExecutor
	Roles                    ServiceRoles
}

func (a EventBridgeTargets) Send(ctx context.Context, request eventbridge.DeliveryRequest) *awswire.Error {
	d := request.Delivery
	target, err := arn.Parse(d.TargetARN)
	if err != nil {
		return &awswire.Error{Code: "InternalFailure", Message: "Invalid retained EventBridge target ARN.", StatusCode: 500}
	}
	ctx, rejected := a.targetContext(ctx, request, target)
	if rejected != nil {
		return rejected
	}
	metadata := awsctx.FromContext(ctx)
	metadata.TraceHeader = request.Event.TraceHeader
	ctx = awsctx.WithMetadata(ctx, metadata)
	if target.Service == "events" && strings.HasPrefix(target.Resource, "event-bus/") {
		return a.Events.ForwardToBus(ctx, d.TargetARN, request.Event)
	}
	body, err := request.Payload()
	if err != nil {
		return &awswire.Error{Code: "InternalFailure", Message: "Invalid retained EventBridge event.", StatusCode: 500}
	}
	switch target.Service {
	case "events":
		if a.APIDestinations == nil || !strings.HasPrefix(target.Resource, "api-destination/") {
			return &awswire.Error{Code: "InternalFailure", Message: "API destination delivery is not configured.", StatusCode: 500}
		}
		return a.APIDestinations.InvokeAPIDestination(ctx, d.TargetARN, d.HttpParameters, body, nil)
	case "sqs":
		return a.sendSQS(ctx, request, body)
	case "sns":
		message, topic := snsapi.Message(body), snsapi.TopicARN(d.TargetARN)
		_, rejected := a.SNS.Publish(ctx, &snsapi.PublishInput{TopicArn: &topic, Message: &message})
		return rejected
	case "lambda":
		_, rejected := a.Lambda.InvokeEvent(ctx, d.TargetARN, []byte(body), d.RuleARN)
		return rejected
	case "logs":
		return a.sendLogs(ctx, request, target, body)
	case "ecs":
		return a.sendECS(ctx, request, body)
	case "kinesis":
		return a.sendKinesis(ctx, request, body)
	case "firehose":
		return a.sendFirehose(ctx, target, body)
	case "codepipeline":
		return a.sendCodePipeline(ctx, request, target, body)
	case "states":
		if target.AccountID == "" && target.Resource == ":" {
			// Only the managed Step Functions rule owner admits this target.
			// Its retained delivery never assumes the workflow execution role.
			if a.StepFunctionsCompletions == nil {
				return &awswire.Error{Code: "InternalFailure", Message: "Step Functions completion delivery is not configured.", StatusCode: 500}
			}
			if err := a.StepFunctionsCompletions.NotifyCompletion(ctx, json.RawMessage(body)); err != nil {
				var rejected *awswire.Error
				if errors.As(err, &rejected) {
					return rejected
				}
				return &awswire.Error{Code: "InternalFailure", Message: "Step Functions completion delivery failed.", StatusCode: 500, Cause: err}
			}
			return nil
		}
		machine, input := stepfunctionsapi.Arn(d.TargetARN), stepfunctionsapi.SensitiveData(body)
		_, rejected := a.StepFunctions.StartExecution(ctx, &stepfunctionsapi.StartExecutionInput{StateMachineArn: &machine, Input: &input})
		return rejected
	default:
		return &awswire.Error{Code: "NotImplementedException", Message: "Unsupported EventBridge target service: " + target.Service, StatusCode: 501}
	}
}

func (a EventBridgeTargets) sendSQS(ctx context.Context, request eventbridge.DeliveryRequest, payload string) *awswire.Error {
	body := api.String(payload)
	in := &api.SendMessageInput{MessageBody: &body}
	if request.Event.TraceHeader != "" {
		kind, trace := api.String("String"), api.String(request.Event.TraceHeader)
		in.MessageSystemAttributes = api.MessageBodySystemAttributeMap{
			"AWSTraceHeader": {DataType: &kind, StringValue: &trace},
		}
	}
	if request.Delivery.MessageGroupID != "" {
		group := api.String(request.Delivery.MessageGroupID)
		in.MessageGroupId = &group
	}
	if len(request.Attributes) != 0 {
		in.MessageAttributes = make(api.MessageBodyAttributeMap, len(request.Attributes))
		for name, value := range request.Attributes {
			kind, value := api.String("String"), api.String(value)
			in.MessageAttributes[api.String(name)] = api.MessageAttributeValue{DataType: &kind, StringValue: &value}
		}
	}
	_, err := a.SQS.SendToQueue(ctx, request.Delivery.TargetARN, in)
	return err
}
