package integrations

import (
	"context"
	"encoding/json"
	"strings"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudwatch"
	"stackd/internal/services/eventbridge"
)

// EventBridgeEventPublisher accepts a producer-owned native service event.
type EventBridgeEventPublisher interface {
	PublishEvent(context.Context, eventbridge.EventRecord) error
}

// CloudWatchEvents admits alarm-owned native events in the source transaction,
// independently of CloudTrail trails and customer PutEvents authorization.
type CloudWatchEvents struct {
	Publisher EventBridgeEventPublisher
}

var _ cloudwatch.AlarmEventPublisher = CloudWatchEvents{}

func (a CloudWatchEvents) PublishAlarmEvent(ctx context.Context, event cloudwatch.AlarmEvent) error {
	origin := awsctx.FromContext(ctx)
	alarm := event.Alarm
	alarmARN := alarm.ARN()
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: alarm.Partition, AccountID: alarm.AccountID, Region: alarm.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "monitoring.amazonaws.com", SourceARN: alarmARN, Type: "AWSService"},
	})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID: event.ID,
		Bus: eventbridge.BusKey{
			Scope: eventbridge.Scope{Partition: alarm.Partition, Account: alarm.AccountID, Region: alarm.Region},
			Name:  "default",
		},
		Source: "aws.cloudwatch", DetailType: event.DetailType, Detail: string(event.Detail),
		Resources: []string{alarmARN}, Time: event.At,
		Account: alarm.AccountID, RequestID: origin.RequestID,
	})
}

// ScalingPolicyInvoker consumes the comparison and reason data accepted by CloudWatch.
type ScalingPolicyInvoker interface {
	ApplyAlarm(context.Context, string, cloudwatch.ScalingAlarmSignal) *awswire.Error
}

// CloudWatchAlarmActions delivers alarm-owned documents through the destination's
// ordinary authorization and asynchronous acceptance boundary.
type CloudWatchAlarmActions struct {
	Lambda      LambdaInvoker
	SNS         SNSPublisher
	Scaling     ScalingPolicyInvoker
	AutoScaling ScalingPolicyInvoker
}

var _ cloudwatch.AlarmActionSender = (*CloudWatchAlarmActions)(nil)

func (a *CloudWatchAlarmActions) Send(ctx context.Context, action cloudwatch.AlarmActionRecord) *awswire.Error {
	alarm := action.Key
	service := strings.SplitN(action.TargetARN, ":", 4)[2]
	principal := "lambda.alarms.cloudwatch.amazonaws.com"
	if service == "sns" || service == "autoscaling" {
		principal = "cloudwatch.amazonaws.com"
	}
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: alarm.Partition, AccountID: alarm.AccountID, Region: alarm.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		ServicePrincipal: awsctx.ServicePrincipal{
			Name: principal, SourceARN: alarm.ARN(), Type: "AWSService",
		},
	})
	if service == "autoscaling" {
		var signal cloudwatch.ScalingAlarmSignal
		if err := json.Unmarshal(action.Payload, &signal); err != nil {
			return &awswire.Error{Code: "InternalFailure", Message: "Unable to decode the retained scaling alarm action.", StatusCode: 500}
		}
		_, policyResource, _ := strings.Cut(action.TargetARN, ":scalingPolicy:")
		_, owner, _ := strings.Cut(policyResource, ":")
		if strings.HasPrefix(owner, "autoScalingGroupName/") {
			return a.AutoScaling.ApplyAlarm(ctx, action.TargetARN, signal)
		}
		return a.Scaling.ApplyAlarm(ctx, action.TargetARN, signal)
	}
	if service == "sns" {
		_, rejected := a.SNS.Publish(ctx, &api.PublishInput{
			TopicArn:         (*api.TopicARN)(&action.TargetARN),
			Message:          new(api.Message(action.Payload)),
			MessageStructure: new(api.MessageStructure("json")),
			Subject:          (*api.Subject)(&action.Subject),
		})
		return rejected
	}
	_, rejected := a.Lambda.InvokeEvent(ctx, action.TargetARN, action.Payload, "")
	return rejected
}
