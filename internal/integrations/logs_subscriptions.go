package integrations

import (
	"context"
	"encoding/json"
	"strings"

	firehoseapi "stackd/internal/awsapi/firehose"
	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/identity"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/logs"
)

// LambdaSubscriptionInvoker exposes permission preflight and real asynchronous
// acceptance; a successful permission check does not execute customer code.
type LambdaSubscriptionInvoker interface {
	LambdaInvoker
	CheckInvoke(context.Context, string) *awswire.Error
}

// LogsSubscriptions enters ordinary target commands under the Logs service
// principal for Lambda or a freshly trust-authorized role session for Kinesis.
// Destination bytes and authority come from the source-owned retained delivery.
type LogsSubscriptions struct {
	Lambda   LambdaSubscriptionInvoker
	Roles    ServiceRoles
	Kinesis  LogsKinesisStreams
	Firehose FirehoseRecordWriter
}

func (a *LogsSubscriptions) Check(ctx context.Context, delivery logs.SubscriptionDelivery) *awswire.Error {
	if strings.Contains(delivery.DestinationARN, ":lambda:") {
		if a.Lambda == nil {
			return logsSubscriptionUnavailable()
		}
		return a.Lambda.CheckInvoke(logsSubscriptionContext(ctx, delivery.Group), delivery.DestinationARN)
	}
	// A real CONTROL_MESSAGE verifies role trust, stream readiness, KMS and
	// PutRecord authority; successful preflight does not commit source state.
	return a.Send(ctx, delivery)
}

func logsSubscriptionContext(ctx context.Context, source logs.GroupKey) context.Context {
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: source.Partition, AccountID: source.AccountID, Region: source.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
	})
	return awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{
		Name: "logs.amazonaws.com", SourceARN: source.ARN() + ":*", Type: "AWSService",
		Aliases: []string{"logs." + source.Region + ".amazonaws.com"},
	})
}

func (a *LogsSubscriptions) Send(ctx context.Context, delivery logs.SubscriptionDelivery) *awswire.Error {
	if !strings.Contains(delivery.DestinationARN, ":lambda:") {
		return a.sendStream(ctx, delivery)
	}
	if a.Lambda == nil {
		return logsSubscriptionUnavailable()
	}
	var envelope struct {
		Logs struct {
			Data []byte `json:"data"`
		} `json:"awslogs"`
	}
	envelope.Logs.Data = delivery.Payload
	// This closed wire shape contains only bytes; JSON encodes them as base64.
	payload, _ := json.Marshal(envelope)
	_, rejected := a.Lambda.InvokeEvent(logsSubscriptionContext(ctx, delivery.Group), delivery.DestinationARN, payload, "")
	return rejected
}

func (a *LogsSubscriptions) sendStream(ctx context.Context, delivery logs.SubscriptionDelivery) *awswire.Error {
	source := awsctx.ServicePrincipal{Name: "logs.amazonaws.com", Aliases: []string{"logs." + delivery.Group.Region + ".amazonaws.com"}, SourceARN: delivery.RoleSourceARN, Type: "AWSService"}
	credential, rejected := a.Roles.assume(ctx, source, delivery.RoleARN, identity.RoleSessionSpec{SessionName: "CloudWatchLogs"}, "")
	if rejected != nil {
		return rejected
	}
	target := strings.SplitN(delivery.TargetARN, ":", 6)
	roleContext, rejected := serviceRoleRequestContext(ctx, credential, target[3], "logs.amazonaws.com")
	if rejected != nil {
		return rejected
	}
	if target[2] == "firehose" {
		if a.Firehose == nil {
			return logsSubscriptionUnavailable()
		}
		name := strings.TrimPrefix(target[5], "deliverystream/")
		_, rejected = a.Firehose.PutRecord(roleContext, &firehoseapi.PutRecordInput{DeliveryStreamName: new(firehoseapi.DeliveryStreamName(name)), Record: &firehoseapi.Record{Data: delivery.Payload}})
		return rejected
	}
	if a.Kinesis == nil {
		return logsSubscriptionUnavailable()
	}
	_, rejected = a.Kinesis.PutRecord(roleContext, &kinesisapi.PutRecordInput{StreamARN: new(kinesisapi.StreamARN(delivery.TargetARN)), PartitionKey: new(kinesisapi.PartitionKey(delivery.PartitionKey)), Data: kinesisapi.Data(delivery.Payload)})
	return rejected
}

// LogsKinesisStreams is satisfied by Kinesis's ordinary authorized command owner.
// PutRecord itself checks current stream readiness; role policies need not grant
// an undocumented DescribeStream permission just to deliver logs.
type LogsKinesisStreams interface {
	PutRecord(context.Context, *kinesisapi.PutRecordInput) (*kinesisapi.PutRecordOutput, *awswire.Error)
}

func logsSubscriptionUnavailable() *awswire.Error {
	return &awswire.Error{Code: "ServiceUnavailableException", Message: "The subscription destination is not configured.", StatusCode: 500}
}
