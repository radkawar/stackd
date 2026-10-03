package integrations

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	eventsapi "stackd/internal/awsapi/eventbridge"
	s3api "stackd/internal/awsapi/s3"
	snsapi "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/lambda"
)

type LambdaOutcomeQueues interface {
	SQSSender
	CheckSendToQueue(context.Context, string) *awswire.Error
}

type LambdaOutcomeTopics interface {
	SNSPublisher
	CheckPublish(context.Context, string) *awswire.Error
}

type LambdaOutcomeEvents interface {
	CheckPutEvents(context.Context, string) *awswire.Error
	PutEvents(context.Context, *eventsapi.PutEventsInput) (*eventsapi.PutEventsOutput, *awswire.Error)
}

type LambdaOutcomeObjects interface {
	HeadBucket(context.Context, *s3api.HeadBucketInput) (*s3api.HeadBucketOutput, *awswire.Error)
	CheckPutObject(context.Context, string, string) *awswire.Error
	PutObject(context.Context, *s3api.PutObjectInput) (*s3api.PutObjectOutput, *awswire.Error)
}

// LambdaOutcomes performs platform delivery under the execution role. Unlike
// customer runtime credentials, these sessions omit lambda:SourceFunctionArn.
// Admission checks do not publish synthetic events or object markers.
type LambdaOutcomes struct {
	Roles  ServiceRoles
	SQS    LambdaOutcomeQueues
	SNS    LambdaOutcomeTopics
	Lambda LambdaSubscriptionInvoker
	Events LambdaOutcomeEvents
	S3     LambdaOutcomeObjects
}

func (a *LambdaOutcomes) Check(ctx context.Context, function lambda.FunctionKey, roleARN, destinationARN string) *awswire.Error {
	return a.checkDestination(ctx, function, roleARN, destinationARN, "aws/lambda/async/"+function.Name+"/*")
}

func (a *LambdaOutcomes) checkDestination(ctx context.Context, function lambda.FunctionKey, roleARN, destinationARN, objectPattern string) *awswire.Error {
	// The Lambda configuration boundary owns ARN/type validation.
	target, _ := arn.Parse(destinationARN)
	ctx, rejected := a.roleContext(ctx, function, roleARN, target.Region)
	if rejected != nil {
		return rejected
	}
	switch target.Service {
	case "sqs":
		return a.SQS.CheckSendToQueue(ctx, destinationARN)
	case "sns":
		return a.SNS.CheckPublish(ctx, destinationARN)
	case "lambda":
		return a.Lambda.CheckInvoke(ctx, destinationARN)
	case "events":
		return a.Events.CheckPutEvents(ctx, destinationARN)
	case "s3":
		if _, rejected := a.S3.HeadBucket(ctx, &s3api.HeadBucketInput{Bucket: new(s3api.BucketName(target.Resource))}); rejected != nil {
			return rejected
		}
		return a.S3.CheckPutObject(ctx, target.Resource, objectPattern)
	default:
		return &awswire.Error{Code: "NotImplementedException", Message: "Unsupported Lambda outcome destination.", StatusCode: 501}
	}
}

func (a *LambdaOutcomes) Send(ctx context.Context, invocation lambda.InvocationRecord, delivery lambda.OutcomeDeliveryRecord) *awswire.Error {
	target, _ := arn.Parse(delivery.DestinationARN)
	ctx, rejected := a.roleContext(ctx, invocation.Key, invocation.RoleARN, target.Region)
	if rejected != nil {
		return rejected
	}
	payload := invocation.Payload
	var attributes snsapi.MessageAttributeMap
	if delivery.DeadLetter {
		var message string
		switch {
		case invocation.Completion == "ZeroReservedConcurrency":
			message = "Function not invoked. Function isconfigured with zero reserved concurrent executions"
		case invocation.ResponseStatus == 429:
			message = "Rate Exceeded."
		case invocation.ResponseStatus == 404:
			// Deleted-target DLQs use the qualified requested resource; native
			// unqualified whole-function deletion makes $LATEST explicit too.
			message = "Function not found: " + invocation.OutcomeFunctionARN()
		case invocation.ResponseStatus == 0:
			// TODO: Comeback capture non-concurrency initialization and permission service failures before adding their native dead-letter error projection.
			return &awswire.Error{Code: "NotImplementedException", Message: "Dead-letter projection for this unexecuted Lambda service failure is not implemented.", StatusCode: 501}
		default:
			var response struct {
				ErrorMessage string `json:"errorMessage"`
			}
			if err := json.Unmarshal(invocation.ResponsePayload, &response); err != nil {
				return &awswire.Error{Code: "InternalFailure", Message: "Cannot decode the Lambda error response: " + err.Error(), StatusCode: 500}
			}
			message = response.ErrorMessage
		}
		if len(message) > 1024 {
			message = strings.ToValidUTF8(message[:1024], "\ufffd")
		}
		attributes = snsapi.MessageAttributeMap{
			"RequestID":    {DataType: new(snsapi.String("String")), StringValue: new(snsapi.String(invocation.RequestID))},
			"ErrorMessage": {DataType: new(snsapi.String("String")), StringValue: new(snsapi.String(message))},
		}
		if invocation.Completion != "ZeroReservedConcurrency" {
			attributes["ErrorCode"] = snsapi.MessageAttributeValue{DataType: new(snsapi.String("Number")), StringValue: new(snsapi.String(strconv.Itoa(invocation.ResponseStatus)))}
		}
	} else {
		var err error
		payload, err = invocation.DestinationPayload()
		if err != nil {
			return &awswire.Error{Code: "InternalFailure", Message: "Cannot encode the Lambda invocation record: " + err.Error(), StatusCode: 500}
		}
	}
	switch target.Service {
	case "sqs", "sns":
		return a.sendDocument(ctx, target, delivery.DestinationARN, payload, attributes, "")
	case "lambda":
		_, rejected := a.Lambda.InvokeEvent(ctx, delivery.DestinationARN, payload, "")
		return rejected
	case "events":
		kind := "Failure"
		if invocation.Completion == "Success" {
			kind = "Success"
		}
		output, rejected := a.Events.PutEvents(ctx, &eventsapi.PutEventsInput{Entries: eventsapi.PutEventsRequestEntryList{{
			EventBusName: new(eventsapi.NonPartnerEventBusNameOrArn(delivery.DestinationARN)),
			Source:       new(eventsapi.String("lambda")), DetailType: new(eventsapi.String("Lambda Function Invocation Result - " + kind)),
			Detail: new(eventsapi.String(payload)), Time: new(eventsapi.Timestamp(invocation.Completed.Truncate(time.Second))),
			Resources: eventsapi.EventResourceList{eventsapi.EventResource(delivery.DestinationARN), eventsapi.EventResource(invocation.OutcomeFunctionARN())},
		}}})
		if rejected != nil {
			return rejected
		}
		if entry := output.Entries[0]; entry.ErrorCode != nil {
			return &awswire.Error{Code: string(*entry.ErrorCode), Message: string(*entry.ErrorMessage), StatusCode: 400}
		}
		return nil
	case "s3":
		key := "aws/lambda/async/" + invocation.Key.Name + "/" + invocation.Completed.UTC().Format("2006/01/02/2006-01-02T15.04.05") + "-" + delivery.ID
		return a.sendDocument(ctx, target, delivery.DestinationARN, payload, nil, key)
	default:
		return &awswire.Error{Code: "NotImplementedException", Message: "Unsupported Lambda outcome destination.", StatusCode: 501}
	}
}

func (a *LambdaOutcomes) roleContext(ctx context.Context, function lambda.FunctionKey, roleARN, targetRegion string) (context.Context, *awswire.Error) {
	parent := awsctx.FromContext(ctx).ParentEventID
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: function.Partition, AccountID: function.Account, Region: function.Region, ParentEventID: parent})
	credential, rejected := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: "lambda.amazonaws.com", SourceARN: function.ARN(), Type: "AWSService"}, roleARN, identity.RoleSessionSpec{SessionName: function.Name}, "")
	if rejected != nil {
		return ctx, rejected
	}
	if targetRegion == "" {
		targetRegion = function.Region
	}
	return serviceRoleRequestContext(ctx, credential, targetRegion, "lambda.amazonaws.com")
}
