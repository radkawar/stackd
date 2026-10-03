package integrations

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/logs"
)

// CloudTrailLogsAPI separates preflight checks from actual resource/message
// commands. Checking write permission must not inject a synthetic log message.
type CloudTrailLogsAPI interface {
	CreateLogStream(context.Context, *api.CreateLogStreamRequest) (*api.Unit, *awswire.Error)
	EnsureLogStream(context.Context, string, string) *awswire.Error
	CheckPutLogEvents(context.Context, string, string) *awswire.Error
	PutLogEvents(context.Context, *api.PutLogEventsRequest) (*api.PutLogEventsResponse, *awswire.Error)
}

// CloudTrailLogs uses CloudTrail's execution role, not the configuring caller's
// permissions. Calls never run within a CloudTrail resource transaction.
type CloudTrailLogs struct {
	Logs  CloudTrailLogsAPI
	Roles ServiceRoles
	Clock clock.Clock
}

func (a CloudTrailLogs) Validate(ctx context.Context, trail cloudtrail.TrailRecord, parent string) *awswire.Error {
	if wire := a.Roles.Authorizer.Authorize(ctx, authorization.Request{
		Action: "iam:PassRole", ResourceARN: trail.LogsRoleARN,
		Context: map[string][]string{"iam:PassedToService": {"cloudtrail.amazonaws.com"}, "iam:AssociatedResourceArn": {trail.Key.ARN()}},
	}); wire != nil {
		return wire
	}
	ctx, wire := a.roleContext(ctx, trail.Key, trail.LogsRoleARN, parent)
	if wire != nil {
		return wire
	}
	group := trailLogGroupName(trail.LogsGroupARN)
	stream := trail.Key.AccountID + "_CloudTrail_" + trail.Key.Region
	if trail.OrganizationID != "" {
		stream = trail.OrganizationID + "_" + stream
	}
	_, wire = a.Logs.CreateLogStream(trailLogsCommand(ctx), &api.CreateLogStreamRequest{
		LogGroupName: new(api.LogGroupName(group)), LogStreamName: new(api.LogStreamName(stream)),
	})
	if wire != nil && wire.Code != "ResourceAlreadyExistsException" {
		return trailLogsPreflightError(wire)
	}
	// Stream creation is already committed. A subsequent permission failure must
	// leave it intact, as observed during native CreateTrail preflight.
	return trailLogsPreflightError(a.Logs.CheckPutLogEvents(ctx, group, stream))
}

func (a CloudTrailLogs) Write(ctx context.Context, batch cloudtrail.DeliveryRecord, records []json.RawMessage, parent string) *awswire.Error {
	ctx, wire := a.roleContext(ctx, batch.Trail, batch.LogsRoleARN, parent)
	if wire != nil {
		return wire
	}
	group := trailLogGroupName(batch.LogsGroupARN)
	// One deterministic delivery shard uses AWS's account/region/suffix shape.
	// TODO: Comeback model native stream allocation and throughput-driven sharding; a captured _3 suffix is not an allocation rule.
	stream := batch.AccountID + "_CloudTrail_" + batch.Region + "_1"
	if batch.OrganizationID != "" {
		stream = batch.OrganizationID + "_" + stream
	}
	if wire := a.Logs.EnsureLogStream(trailLogsCommand(ctx), group, stream); wire != nil {
		return wire
	}
	timestamp := api.Timestamp(a.Clock.Now().UnixMilli())
	events := make(api.InputLogEvents, 0, min(len(records), logs.MaxBatchEvents))
	size := 0
	flush := func() *awswire.Error {
		out, wire := a.Logs.PutLogEvents(trailLogsCommand(ctx), &api.PutLogEventsRequest{
			LogGroupName: new(api.LogGroupName(group)), LogStreamName: new(api.LogStreamName(stream)), LogEvents: events,
		})
		if wire != nil {
			return wire
		}
		if out.RejectedLogEventsInfo != nil {
			return &awswire.Error{Code: "InvalidParameterException", Message: "CloudWatch Logs rejected CloudTrail delivery timestamps.", StatusCode: 400}
		}
		events, size = events[:0], 0
		return nil
	}
	for _, record := range records {
		bytes := len(record) + logs.EventOverheadBytes
		if bytes > logs.MaxBatchBytes {
			return &awswire.Error{Code: "InvalidParameterException", Message: "The CloudTrail record exceeds the CloudWatch Logs event size limit.", StatusCode: 400}
		}
		if len(events) == logs.MaxBatchEvents || size+bytes > logs.MaxBatchBytes {
			if wire := flush(); wire != nil {
				return wire
			}
		}
		message := api.EventMessage(string(record))
		events = append(events, api.InputLogEvent{Message: &message, Timestamp: &timestamp})
		size += bytes
	}
	if len(events) != 0 {
		return flush()
	}
	return nil
}

func (a CloudTrailLogs) roleContext(ctx context.Context, trail cloudtrail.TrailKey, roleARN, parent string) (context.Context, *awswire.Error) {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: trail.Partition, AccountID: trail.AccountID, Region: trail.Region, ParentEventID: parent})
	credential, wire := a.Roles.assume(ctx,
		awsctx.ServicePrincipal{Name: "cloudtrail.amazonaws.com", SourceARN: trail.ARN(), Type: "AWSService"},
		roleARN, identity.RoleSessionSpec{SessionName: "CloudTrail_LogsDelivery"}, "")
	if wire != nil {
		if wire.StatusCode >= 500 {
			return ctx, wire
		}
		return ctx, &awswire.Error{Code: "InvalidCloudWatchLogsRoleArnException", Message: "CloudTrail cannot assume the log delivery role. " + wire.Message, StatusCode: 400}
	}
	metadata, err := identity.RequestMetadata(credential, credential.AccessKeyID, trail.Region, uuid.NewString())
	if err != nil {
		return ctx, serviceRoleFailure(err)
	}
	metadata.ParentEventID = parent
	metadata.SourceIP, metadata.UserAgent = "cloudtrail.amazonaws.com", "cloudtrail.amazonaws.com"
	metadata.InvokedBy = "cloudtrail.amazonaws.com"
	return awsctx.WithMetadata(ctx, metadata), nil
}

func trailLogGroupName(arn string) string {
	// The CloudTrail configuration boundary already validates this ARN and scope.
	_, name, _ := strings.Cut(arn, ":log-group:")
	return strings.TrimSuffix(name, ":*")
}

func trailLogsCommand(ctx context.Context) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	return awsctx.WithMetadata(ctx, metadata)
}

func trailLogsPreflightError(wire *awswire.Error) *awswire.Error {
	if wire == nil || wire.StatusCode >= 500 {
		return wire
	}
	return &awswire.Error{Code: "InvalidCloudWatchLogsLogGroupArnException", Message: "CloudTrail cannot validate log delivery to the specified group. " + wire.Message, StatusCode: 400}
}
