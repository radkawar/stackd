package integrations

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	logsapi "stackd/internal/awsapi/logs"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/ec2"
	"stackd/internal/services/logs"
)

// FlowLogObjects admits and delivers real objects through the S3 owner. The
// preflight uses the same requested ACL without creating a probe object.
type FlowLogObjects interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	GetBucketACL(context.Context, *s3api.GetBucketAclInput) (*s3api.GetBucketAclOutput, *awswire.Error)
	CheckPutObject(context.Context, *s3api.PutObjectInput) *awswire.Error
	PutObject(context.Context, *s3api.PutObjectInput) (*s3api.PutObjectOutput, *awswire.Error)
}

type FlowLogEvents interface {
	EnsureLogGroup(context.Context, string) *awswire.Error
	EnsureLogStream(context.Context, string, string) *awswire.Error
	PutLogEvents(context.Context, *logsapi.PutLogEventsRequest) (*logsapi.PutLogEventsResponse, *awswire.Error)
}

type FlowLogSubscriptions interface {
	View(context.Context, func(ec2.Reader) error) error
}

// EC2FlowLogs never retains the configuring caller's credentials. Every delivery
// obtains current destination authority outside the EC2 resource transaction.
type EC2FlowLogs struct {
	S3            FlowLogObjects
	Logs          FlowLogEvents
	Roles         ServiceRoles
	Subscriptions FlowLogSubscriptions
	policyMu      sync.Mutex
}

func flowLogARN(key ec2.ResourceKey) string {
	return "arn:" + key.Scope.Partition + ":ec2:" + key.Scope.Region + ":" + key.Scope.AccountID + ":vpc-flow-log/" + key.ID
}

func flowLogDeliveryError(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidParameter", Message: message, StatusCode: 400}
}

func (a *EC2FlowLogs) Validate(ctx context.Context, record ec2.FlowLogRecord) *awswire.Error {
	switch record.DestinationType {
	case "cloud-watch-logs":
		if a.Logs == nil {
			return flowLogDeliveryError("CloudWatch Logs delivery is unavailable.")
		}
		if wire := a.Roles.Authorizer.Authorize(ctx, authorization.Request{
			Action: "iam:PassRole", ResourceARN: record.PermissionARN,
			Context: map[string][]string{"iam:PassedToService": {"vpc-flow-logs.amazonaws.com"}, "iam:AssociatedResourceArn": {flowLogARN(record.Key)}},
		}); wire != nil {
			return wire
		}
		execution, wire := a.roleContext(ctx, record.Key, record.PermissionARN)
		if wire != nil {
			return wire
		}
		// A VPC can have no interfaces. Do not create a fictitious ENI stream or
		// inject a test event to validate that legitimate empty subscription.
		return a.Logs.EnsureLogGroup(execution, record.LogGroupName)
	case "s3":
		// Serialize feature-owned read/merge/write policy admission. Each S3
		// command still checks the caller's current authorization.
		a.policyMu.Lock()
		defer a.policyMu.Unlock()
		if wire := a.validateS3(ctx, record); wire != nil {
			return wire
		}
		return a.initializeS3(ctx, record)
	default:
		return flowLogDeliveryError("The flow log destination type is not supported.")
	}
}

func (a *EC2FlowLogs) roleContext(ctx context.Context, key ec2.ResourceKey, role string) (context.Context, *awswire.Error) {
	parent := awsctx.FromContext(ctx).ParentEventID
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ParentEventID: parent})
	credential, wire := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: "vpc-flow-logs.amazonaws.com", SourceARN: flowLogARN(key), Type: "AWSService"}, role, identity.RoleSessionSpec{SessionName: "VPCFlowLogs"}, "")
	if wire != nil {
		if wire.StatusCode >= 500 {
			return ctx, wire
		}
		return ctx, flowLogDeliveryError("Unable to assume given IAM role. " + wire.Message)
	}
	metadata, err := identity.RequestMetadata(credential, credential.AccessKeyID, key.Scope.Region, uuid.NewString())
	if err != nil {
		return ctx, serviceRoleFailure(err)
	}
	metadata.ParentEventID = parent
	metadata.SourceIP, metadata.UserAgent, metadata.InvokedBy = "vpc-flow-logs.amazonaws.com", "vpc-flow-logs.amazonaws.com", "vpc-flow-logs.amazonaws.com"
	return awsctx.WithMetadata(ctx, metadata), nil
}

func flowLogS3Context(ctx context.Context, key ec2.ResourceKey) context.Context {
	parent := awsctx.FromContext(ctx).ParentEventID
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, RequestID: uuid.NewString(), ParentEventID: parent})
	return awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "delivery.logs.amazonaws.com", SourceARN: "arn:" + key.Scope.Partition + ":logs:" + key.Scope.Region + ":" + key.Scope.AccountID + ":*", Type: "AWSService"})
}

func flowLogCommand(ctx context.Context) context.Context {
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	return awsctx.WithMetadata(ctx, metadata)
}

func (a *EC2FlowLogs) Write(ctx context.Context, batch ec2.FlowLogDeliveryRecord, lines []ec2.FlowLogLine) *awswire.Error {
	if len(lines) == 0 {
		return flowLogDeliveryError("A flow log batch must contain observed records.")
	}
	switch batch.DestinationType {
	case "cloud-watch-logs":
		return a.writeLogs(ctx, batch, lines)
	case "s3":
		return a.writeS3(ctx, batch, lines)
	default:
		return flowLogDeliveryError("The flow log destination type is not supported.")
	}
}

func (a *EC2FlowLogs) writeLogs(ctx context.Context, batch ec2.FlowLogDeliveryRecord, lines []ec2.FlowLogLine) *awswire.Error {
	if a.Logs == nil {
		return flowLogDeliveryError("CloudWatch Logs delivery is unavailable.")
	}
	ctx, wire := a.roleContext(ctx, batch.FlowLogKey, batch.PermissionARN)
	if wire != nil {
		return wire
	}
	if wire = a.Logs.EnsureLogGroup(flowLogCommand(ctx), batch.LogGroupName); wire != nil {
		return wire
	}
	ordered := slices.Clone(lines)
	slices.SortFunc(ordered, func(a, b ec2.FlowLogLine) int {
		if n := strings.Compare(a.InterfaceID, b.InterfaceID); n != 0 {
			return n
		}
		return a.Start.Compare(b.Start)
	})
	for len(ordered) != 0 {
		stream := ordered[0].InterfaceID
		if stream == "" {
			return flowLogDeliveryError("A flow record has no authoritative network interface.")
		}
		if wire := a.Logs.EnsureLogStream(flowLogCommand(ctx), batch.LogGroupName, stream); wire != nil {
			return wire
		}
		events := make(logsapi.InputLogEvents, 0, min(len(ordered), logs.MaxBatchEvents))
		first, size := ordered[0].Start, 0
		for len(ordered) != 0 && ordered[0].InterfaceID == stream {
			line := ordered[0]
			length := len(line.Message) + logs.EventOverheadBytes
			if length > logs.MaxBatchBytes {
				return flowLogDeliveryError("A flow log record exceeds the CloudWatch Logs event limit.")
			}
			if len(events) != 0 && (len(events) == logs.MaxBatchEvents || size+length > logs.MaxBatchBytes || line.Start.Sub(first) > 24*time.Hour) {
				break
			}
			events = append(events, logsapi.InputLogEvent{Message: new(logsapi.EventMessage(line.Message)), Timestamp: new(logsapi.Timestamp(line.Start.UnixMilli()))})
			size += length
			ordered = ordered[1:]
		}
		out, wire := a.Logs.PutLogEvents(flowLogCommand(ctx), &logsapi.PutLogEventsRequest{LogGroupName: new(logsapi.LogGroupName(batch.LogGroupName)), LogStreamName: new(logsapi.LogStreamName(stream)), LogEvents: events})
		if wire != nil {
			return wire
		}
		if out.RejectedLogEventsInfo != nil {
			return flowLogDeliveryError("CloudWatch Logs rejected flow record timestamps.")
		}
	}
	return nil
}

func flowLogBucket(destination string) (bucket, prefix string, wire *awswire.Error) {
	parsed, err := arn.Parse(destination)
	if err != nil || parsed.Service != "s3" || parsed.Region != "" || parsed.AccountID != "" || parsed.Resource == "" {
		return "", "", flowLogDeliveryError("The flow log S3 destination ARN is invalid.")
	}
	bucket, prefix, _ = strings.Cut(parsed.Resource, "/")
	if bucket == "" {
		return "", "", flowLogDeliveryError("The flow log S3 bucket is missing.")
	}
	return bucket, strings.TrimSuffix(prefix, "/"), nil
}

func flowLogS3Prefix(prefix string, key ec2.ResourceKey, hive bool) string {
	if prefix != "" {
		prefix += "/"
	}
	if hive {
		return prefix + "AWSLogs/aws-account-id=" + key.Scope.AccountID + "/aws-service=vpcflowlogs/aws-region=" + key.Scope.Region + "/"
	}
	return prefix + "AWSLogs/" + key.Scope.AccountID + "/vpcflowlogs/" + key.Scope.Region + "/"
}

func flowLogObjectKey(batch ec2.FlowLogDeliveryRecord, prefix string) string {
	stamp := batch.WindowStart.UTC()
	key := flowLogS3Prefix(prefix, batch.FlowLogKey, batch.HivePartitions)
	if batch.HivePartitions {
		key += stamp.Format("year=2006/month=01/day=02/")
		if batch.HourPartitions {
			key += stamp.Format("hour=15/")
		}
	} else {
		key += stamp.Format("2006/01/02/")
		if batch.HourPartitions {
			key += stamp.Format("15/")
		}
	}
	digest := sha256.Sum256([]byte(batch.Key.ID))
	return key + batch.FlowLogKey.Scope.AccountID + "_vpcflowlogs_" + batch.FlowLogKey.Scope.Region + "_" + batch.FlowLogKey.ID + "_" + stamp.Format("20060102T1504Z") + "_" + hex.EncodeToString(digest[:8]) + ".log.gz"
}

func (a *EC2FlowLogs) writeS3(ctx context.Context, batch ec2.FlowLogDeliveryRecord, lines []ec2.FlowLogLine) *awswire.Error {
	if a.S3 == nil {
		return flowLogDeliveryError("S3 flow log delivery is unavailable.")
	}
	bucket, prefix, wire := flowLogBucket(batch.Destination)
	if wire != nil {
		return wire
	}
	if batch.WindowStart.IsZero() || batch.Header == "" {
		return flowLogDeliveryError("A flow log batch has no retained format or capture window.")
	}
	var body bytes.Buffer
	compressed := gzip.NewWriter(&body)
	if _, err := fmt.Fprintln(compressed, batch.Header); err != nil {
		return serviceRoleFailure(err)
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(compressed, line.Message); err != nil {
			return serviceRoleFailure(err)
		}
	}
	if err := compressed.Close(); err != nil {
		return serviceRoleFailure(err)
	}
	ctx = flowLogS3Context(ctx, batch.FlowLogKey)
	if _, wire := a.S3.GetBucketACL(ctx, &s3api.GetBucketAclInput{Bucket: new(s3api.BucketName(bucket))}); wire != nil {
		return wire
	}
	_, wire = a.S3.PutObject(flowLogCommand(ctx), &s3api.PutObjectInput{Bucket: new(s3api.BucketName(bucket)), Key: new(s3api.ObjectKey(flowLogObjectKey(batch, prefix))), Body: body.Bytes(), ACL: new(s3api.ObjectCannedACL("bucket-owner-full-control")), ContentType: new(s3api.ContentType("text/plain")), ContentEncoding: new(s3api.ContentEncoding("gzip"))})
	return wire
}
