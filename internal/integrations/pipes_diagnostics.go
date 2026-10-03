package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	firehoseapi "stackd/internal/awsapi/firehose"
	logsapi "stackd/internal/awsapi/logs"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/pipes"
	"strings"
)

type PipesDiagnostics struct {
	Logs     EventBridgeLogsAPI
	Commands StepFunctionsCommands
}

func (a *PipesDiagnostics) Validate(_ context.Context, p pipes.PipeRecord) *awswire.Error {
	if p.Logging.LogGroupARN != "" {
		v, e := arn.Parse(p.Logging.LogGroupARN)
		if e != nil || v.Service != "logs" || v.Region != p.Key.Region || v.AccountID != p.Key.AccountID || !strings.HasPrefix(v.Resource, "log-group:") {
			return pipesInvalid("Invalid CloudWatch Logs destination.")
		}
		if a.Logs == nil {
			return pipesDependency("CloudWatch Logs")
		}
	}
	if p.Logging.FirehoseARN != "" {
		v, e := arn.Parse(p.Logging.FirehoseARN)
		if e != nil || v.Service != "firehose" || v.Region != p.Key.Region || v.AccountID != p.Key.AccountID {
			return pipesInvalid("Invalid Firehose log destination.")
		}
		if _, _, e := a.Commands.resolve("firehose", "PutRecord"); e != nil {
			return e
		}
	}
	if p.Logging.BucketName != "" {
		if _, _, e := a.Commands.resolve("s3", "PutObject"); e != nil {
			return e
		}
	}
	return nil
}
func (a *PipesDiagnostics) Publish(ctx context.Context, p pipes.PipeRecord, event pipes.ExecutionLog) error {
	origin := awsctx.FromContext(ctx)
	ctx = awsctx.WithServicePrincipal(awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition:     p.Key.Partition,
		AccountID:     p.Key.AccountID,
		Region:        p.Key.Region,
		ParentEventID: origin.ParentEventID,
		RequestID:     uuid.NewString(),
	}), awsctx.ServicePrincipal{
		Name:      "delivery.logs.amazonaws.com",
		SourceARN: "arn:" + p.Key.Partition + ":logs:" + p.Key.Region + ":" + p.Key.AccountID + ":*",
		Type:      "AWSService",
	})
	document := map[string]any{
		"resourceArn": p.Key.ARN(),
		"executionId": event.ID,
		"timestamp":   event.At.UnixMilli(),
		"messageType": event.Stage,
		"logLevel":    event.Level,
	}
	if event.Duration > 0 {
		document["executionDuration"] = event.Duration.Milliseconds()
	}
	if event.Error != "" {
		document["error"] = map[string]string{"message": event.Error}
	}
	if len(event.Payload) > 0 {
		document["payload"] = string(event.Payload)
	}
	body, e := json.Marshal(document)
	if e != nil {
		return e
	}
	if p.Logging.LogGroupARN != "" && len(body) > 256*1024 {
		overhead := len(body) - len(event.Payload) + 128
		keep := max(0, 256*1024-overhead)
		document["payload"] = string(event.Payload[:min(keep, len(event.Payload))])
		document["truncatedFields"] = []string{"payload"}
		body, e = json.Marshal(document)
		if e != nil {
			return e
		}
	}
	var failures []error
	if p.Logging.LogGroupARN != "" {
		target, _ := arn.Parse(p.Logging.LogGroupARN)
		group := strings.TrimSuffix(strings.TrimPrefix(target.Resource, "log-group:"), ":*")
		stream := p.Key.Name + "/" + event.At.UTC().Format("2006/01/02")
		_, rejected := a.Logs.CreateLogStream(ctx, &logsapi.CreateLogStreamInput{LogGroupName: new(logsapi.LogGroupName(group)), LogStreamName: new(logsapi.LogStreamName(stream))})
		if rejected == nil || rejected.Code == "ResourceAlreadyExistsException" {
			out, wire := a.Logs.PutLogEvents(ctx, &logsapi.PutLogEventsInput{
				LogGroupName:  new(logsapi.LogGroupName(group)),
				LogStreamName: new(logsapi.LogStreamName(stream)),
				LogEvents:     logsapi.InputLogEvents{{Timestamp: new(logsapi.Timestamp(event.At.UnixMilli())), Message: new(logsapi.EventMessage(body))}},
			})
			rejected = wire
			if wire == nil && out.RejectedLogEventsInfo != nil {
				failures = append(failures, errors.New("pipes execution log timestamp rejected"))
			}
		}
		if rejected != nil {
			failures = append(failures, rejected)
		}
	}
	if p.Logging.FirehoseARN != "" {
		target, _ := arn.Parse(p.Logging.FirehoseARN)
		_, rejected := a.Commands.CallTyped(ctx, "firehose", "PutRecord", &firehoseapi.PutRecordInput{
			DeliveryStreamName: new(firehoseapi.DeliveryStreamName(strings.TrimPrefix(target.Resource, "deliverystream/"))),
			Record:             &firehoseapi.Record{Data: append(body, '\n')},
		})
		if rejected != nil {
			failures = append(failures, rejected)
		}
	}
	if p.Logging.BucketName != "" {
		objectBody := append(body, '\n')
		key := strings.TrimSuffix(p.Logging.Prefix, "/") + "/AWSLogs/" + p.Key.AccountID + "/Pipes/" + p.Key.Region + "/" + p.Key.Name + "/" + event.At.UTC().Format("2006/01/02/") + event.ID + "-" + event.Stage + ".json"
		key = strings.TrimPrefix(key, "/")
		in := &s3api.PutObjectInput{Bucket: new(s3api.BucketName(p.Logging.BucketName)), Key: new(s3api.ObjectKey(key)), Body: objectBody}
		if p.Logging.BucketOwner != "" {
			in.ExpectedBucketOwner = new(s3api.AccountId(p.Logging.BucketOwner))
		}
		_, rejected := a.Commands.CallTyped(ctx, "s3", "PutObject", in)
		if rejected != nil {
			failures = append(failures, rejected)
		}
	}
	return errors.Join(failures...)
}
