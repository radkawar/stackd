package integrations

import (
	"cmp"
	"context"
	"slices"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/mq"
)

// MQLogs delivers native broker output through the existing Logs owner.
// ActiveMQ group creation uses the caller; its delivery requires a resource
// policy. RabbitMQ creates groups and delivers using its current linked role.
type MQLogs struct {
	Logs  RuntimeLogsAPI
	Roles ServiceRoles
}

var _ mq.LogDelivery = MQLogs{}

func (a MQLogs) Prepare(ctx context.Context, broker mq.BrokerRecord, settings mq.LogSettings) *awswire.Error {
	if a.Logs == nil {
		return mqLogsUnavailable()
	}
	if broker.Engine == "RABBITMQ" {
		var wire *awswire.Error
		ctx, wire = a.rabbitMQContext(ctx, broker)
		if wire != nil {
			return wire
		}
	}
	for _, requested := range []struct {
		kind    mq.LogType
		enabled bool
	}{{mq.GeneralLog, settings.General}, {mq.AuditLog, settings.Audit}} {
		if !requested.enabled {
			continue
		}
		// ActiveMQ retains the caller; RabbitMQ uses its linked role. Existing
		// groups confer no authority and do not bypass current IAM checks.
		_, wire := a.Logs.CreateLogGroup(mqLogCommandContext(ctx), &api.CreateLogGroupRequest{
			LogGroupName: new(api.LogGroupName(mqLogGroup(broker, requested.kind))),
		})
		if wire != nil && wire.Code != "ResourceAlreadyExistsException" {
			return wire
		}
	}
	return nil
}

func (a MQLogs) Write(ctx context.Context, broker mq.BrokerRecord, kind mq.LogType, records []mq.LogRecord) error {
	if a.Logs == nil {
		return mqLogsUnavailable()
	}
	if kind != mq.GeneralLog && kind != mq.AuditLog {
		return &awswire.Error{Code: "InvalidParameterException", Message: "Unknown Amazon MQ log type.", StatusCode: 400}
	}
	if len(records) == 0 {
		return nil
	}
	// Replace, rather than augment, caller metadata. Delivery cannot inherit
	// root credentials, a caller session, or a different routing scope.
	stream := "activemq-" + broker.ID + "-1.log"
	if broker.Engine == "RABBITMQ" {
		if kind != mq.GeneralLog {
			return &awswire.Error{Code: "InvalidParameterException", Message: "RabbitMQ does not support audit logging.", StatusCode: 400}
		}
		var wire *awswire.Error
		ctx, wire = a.rabbitMQContext(ctx, broker)
		if wire != nil {
			return wire
		}
		stream = "rabbitmq-" + broker.ID + "-1.log"
	} else {
		ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
			Partition: broker.Partition, AccountID: broker.AccountID, Region: broker.Region,
			ParentEventID: awsctx.FromContext(ctx).ParentEventID,
			SourceIP:      "mq.amazonaws.com", UserAgent: "mq.amazonaws.com",
			ServicePrincipal: awsctx.ServicePrincipal{Name: "mq.amazonaws.com", SourceARN: broker.ARN, Type: "AWSService"},
		})
	}
	events := make(api.InputLogEvents, len(records))
	for i, record := range records {
		events[i] = api.InputLogEvent{Timestamp: new(api.Timestamp(record.Timestamp.UnixMilli())), Message: new(api.EventMessage(record.Message))}
	}
	// Normalize request order only: native source records, bytes, timestamps
	// and the parent's success-only byte cursor remain unchanged.
	slices.SortStableFunc(events, func(a, b api.InputLogEvent) int {
		return cmp.Compare(*a.Timestamp, *b.Timestamp)
	})
	input := &api.PutLogEventsRequest{
		LogGroupName:  new(api.LogGroupName(mqLogGroup(broker, kind))),
		LogStreamName: new(api.LogStreamName(stream)),
		LogEvents:     events,
	}
	_, wire := a.Logs.PutLogEvents(mqLogCommandContext(ctx), input)
	if wire != nil && wire.Code == "ResourceNotFoundException" {
		_, wire = a.Logs.CreateLogStream(mqLogCommandContext(ctx), &api.CreateLogStreamRequest{
			LogGroupName: input.LogGroupName, LogStreamName: input.LogStreamName,
		})
		if wire != nil && wire.Code == "ResourceNotFoundException" && broker.Engine == "RABBITMQ" {
			_, wire = a.Logs.CreateLogGroup(mqLogCommandContext(ctx), &api.CreateLogGroupRequest{LogGroupName: input.LogGroupName})
			if wire != nil && wire.Code != "ResourceAlreadyExistsException" {
				return wire
			}
			_, wire = a.Logs.CreateLogStream(mqLogCommandContext(ctx), &api.CreateLogStreamRequest{
				LogGroupName: input.LogGroupName, LogStreamName: input.LogStreamName,
			})
		}
		if wire != nil && wire.Code != "ResourceAlreadyExistsException" {
			return wire
		}
		// ActiveMQ never creates groups as the service; RabbitMQ's linked role
		// can. Batches fit one request, so no successful prefix is replayed.
		_, wire = a.Logs.PutLogEvents(mqLogCommandContext(ctx), input)
	}
	if wire != nil {
		return wire
	}
	// As with EKS, success acknowledges the entire source batch, including
	// age/retention rejections. Retrying would duplicate accepted records.
	return nil
}

func (a MQLogs) rabbitMQContext(ctx context.Context, broker mq.BrokerRecord) (context.Context, *awswire.Error) {
	// Scheduled delivery has no API caller. Role resolution and trust use the
	// broker's owning scope, never absent or unrelated incoming metadata.
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: broker.Partition, AccountID: broker.AccountID, Region: broker.Region,
		ParentEventID: awsctx.FromContext(ctx).ParentEventID,
	})
	roleARN := "arn:" + broker.Partition + ":iam::" + broker.AccountID + ":role/aws-service-role/mq.amazonaws.com/AWSServiceRoleForAmazonMQ"
	credential, wire := a.Roles.assume(ctx,
		awsctx.ServicePrincipal{Name: "mq.amazonaws.com", SourceARN: broker.ARN, Type: "AWSService"},
		roleARN, identity.RoleSessionSpec{SessionName: "AmazonMQLogs"}, "")
	if wire != nil {
		return ctx, wire
	}
	return serviceRoleRequestContext(ctx, credential, broker.Region, "mq.amazonaws.com")
}

func mqLogGroup(broker mq.BrokerRecord, kind mq.LogType) string {
	return "/aws/amazonmq/broker/" + broker.ID + "/" + string(kind)
}

func mqLogCommandContext(ctx context.Context) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	return awsctx.WithMetadata(ctx, metadata)
}

func mqLogsUnavailable() *awswire.Error {
	return &awswire.Error{Code: "ServiceUnavailableException", Message: "CloudWatch Logs owner unavailable.", StatusCode: 503}
}
