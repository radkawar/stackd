package integrations

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	native "stackd/compute/eks"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/eks"
	"stackd/internal/services/logs"
)

// EKSLogs uses the existing Logs owner, including its authorization, subscriptions,
// metrics and retention. No log group, stream or event is stored in EKS control state.
type EKSLogs struct {
	Roles ServiceRoles
	Logs  RuntimeLogsAPI
}

func (a EKSLogs) WriteControlPlaneLogs(ctx context.Context, cluster eks.Cluster, records []native.LogRecord) error {
	if a.Logs == nil {
		return errors.New("CloudWatch Logs owner unavailable")
	}
	roleARN := "arn:" + cluster.Key.Partition + ":iam::" + cluster.Key.AccountID + ":role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS"
	credential, rejected := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: "eks.amazonaws.com", SourceARN: cluster.Key.ARN(), Type: "AWSService"}, roleARN, identity.RoleSessionSpec{SessionName: "EKSControlPlaneLogs", Duration: time.Hour}, "")
	if rejected != nil {
		return rejected
	}
	ctx, rejected = serviceRoleRequestContext(ctx, credential, cluster.Key.Region, "eks.amazonaws.com")
	if rejected != nil {
		return rejected
	}
	group := "/aws/eks/" + cluster.Key.Name + "/cluster"
	commandContext := func() context.Context {
		metadata := awsctx.FromContext(ctx)
		metadata.RequestID = uuid.NewString()
		return awsctx.WithMetadata(ctx, metadata)
	}
	flush := func(stream string, events api.InputLogEvents) error {
		// Native audit batches follow concurrent enqueue order, not necessarily
		// event time. Normalize only this request; retain source bytes and times.
		slices.SortStableFunc(events, func(a, b api.InputLogEvent) int {
			return cmp.Compare(*a.Timestamp, *b.Timestamp)
		})
		input := &api.PutLogEventsRequest{LogGroupName: new(api.LogGroupName(group)), LogStreamName: new(api.LogStreamName(stream)), LogEvents: events}
		_, wire := a.Logs.PutLogEvents(commandContext(), input)
		if wire != nil && wire.Code == "ResourceNotFoundException" {
			_, wire = a.Logs.CreateLogStream(commandContext(), &api.CreateLogStreamRequest{LogGroupName: input.LogGroupName, LogStreamName: input.LogStreamName})
			if wire != nil && wire.Code == "ResourceNotFoundException" {
				_, wire = a.Logs.CreateLogGroup(commandContext(), &api.CreateLogGroupRequest{LogGroupName: input.LogGroupName})
				if wire != nil && wire.Code != "ResourceAlreadyExistsException" {
					return wire
				}
				_, wire = a.Logs.CreateLogStream(commandContext(), &api.CreateLogStreamRequest{LogGroupName: input.LogGroupName, LogStreamName: input.LogStreamName})
			}
			if wire != nil && wire.Code != "ResourceAlreadyExistsException" {
				return wire
			}
			_, wire = a.Logs.PutLogEvents(commandContext(), input)
		}
		if wire != nil {
			return wire
		}
		// A successful request acknowledges the batch, including events that
		// CloudWatch skipped for age/retention. Replaying it duplicates accepted
		// events and cannot make permanently rejected timestamps acceptable.
		return nil
	}
	// Bound each native stream's CloudWatch request. flush orders its timestamps
	// without changing the producer's source frame or success-only byte cursor.
	type batch struct {
		events api.InputLogEvents
		size   int
	}
	batches := make(map[string]*batch)
	var order []string
	for _, record := range records {
		size := len(record.Message) + logs.EventOverheadBytes
		if size > logs.MaxBatchBytes {
			return errors.New("EKS source record exceeds CloudWatch Logs maximum event size")
		}
		b := batches[record.Stream]
		if b == nil {
			b = &batch{}
			batches[record.Stream] = b
			order = append(order, record.Stream)
		}
		if b.size+size > logs.MaxBatchBytes || len(b.events) == logs.MaxBatchEvents {
			if err := flush(record.Stream, b.events); err != nil {
				return err
			}
			b.events = b.events[:0]
			b.size = 0
		}
		b.events = append(b.events, api.InputLogEvent{Timestamp: new(api.Timestamp(record.Timestamp.UnixMilli())), Message: new(api.EventMessage(record.Message))})
		b.size += size
	}
	for _, stream := range order {
		if err := flush(stream, batches[stream].events); err != nil {
			return err
		}
	}
	return nil
}
