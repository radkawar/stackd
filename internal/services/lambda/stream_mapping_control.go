package lambda

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

type streamMappingControl struct {
	s      *Service
	source string
}

func (c streamMappingControl) createSettings(in *api.CreateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	v := EventSourceMappingSettings{BatchSize: 100, Stream: &StreamMappingSettings{StartingPosition: value(in.StartingPosition), ParallelizationFactor: 1, MaximumRetryAttempts: -1, MaximumRecordAge: -time.Second}}
	if v.Stream.StartingPosition != "TRIM_HORIZON" && v.Stream.StartingPosition != "LATEST" && !(c.source == "kinesis" && v.Stream.StartingPosition == "AT_TIMESTAMP") {
		return v, mappingParameter("Invalid stream StartingPosition.")
	}
	if in.StartingPositionTimestamp != nil {
		if c.source != "kinesis" || v.Stream.StartingPosition != "AT_TIMESTAMP" {
			return v, mappingParameter("StartingPositionTimestamp requires Kinesis AT_TIMESTAMP.")
		}
		v.Stream.StartingPositionTimestamp = time.Time(*in.StartingPositionTimestamp)
		if v.Stream.StartingPositionTimestamp.After(c.s.clock.Now()) {
			return v, mappingParameter("StartingPositionTimestamp cannot be in the future.")
		}
	} else if v.Stream.StartingPosition == "AT_TIMESTAMP" {
		return v, mappingParameter("StartingPositionTimestamp is required for AT_TIMESTAMP.")
	}
	if in.Topics != nil || in.Queues != nil || in.SelfManagedEventSource != nil {
		return v, mappingParameter("Kafka and MQ configuration is not supported for stream mappings.")
	}
	return c.updateSettings(v, mappingSettingsInput(in))
}

func (c streamMappingControl) updateSettings(v EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error) {
	if in.ScalingConfig != nil || in.ProvisionedPollerConfig != nil || in.AmazonManagedKafkaEventSourceConfig != nil || in.SelfManagedKafkaEventSourceConfig != nil || in.SourceAccessConfigurations != nil || in.DocumentDBEventSourceConfig != nil || in.LoggingConfig != nil {
		return v, mappingParameter("Queue, Kafka, MQ, DocumentDB, provisioned poller and logging configuration is not supported for stream mappings.")
	}
	var wire *awswire.Error
	v, wire = applyCommonMappingSettings(v, in)
	if wire != nil {
		return v, wire
	}
	d := *v.Stream
	if in.MaximumRecordAgeInSeconds != nil {
		age := int(*in.MaximumRecordAgeInSeconds)
		if age != -1 && age < 60 {
			return v, mappingParameter("MaximumRecordAgeInSeconds must be -1 or at least 60 for stream mappings.")
		}
		d.MaximumRecordAge = time.Duration(age) * time.Second
	}
	if in.MaximumRetryAttempts != nil {
		d.MaximumRetryAttempts = int(*in.MaximumRetryAttempts)
	}
	if in.ParallelizationFactor != nil {
		d.ParallelizationFactor = int(*in.ParallelizationFactor)
	}
	if in.BisectBatchOnFunctionError != nil {
		d.BisectBatchOnFunctionError = bool(*in.BisectBatchOnFunctionError)
	}
	if in.TumblingWindowInSeconds != nil {
		d.TumblingWindow = time.Duration(*in.TumblingWindowInSeconds) * time.Second
	}
	if in.DestinationConfig != nil {
		if in.DestinationConfig.OnSuccess != nil {
			return v, mappingParameter("OnSuccess configuration is not supported for event source mappings.")
		}
		if in.DestinationConfig.OnFailure != nil {
			d.OnFailure = value(in.DestinationConfig.OnFailure.Destination)
		}
	}
	if d.TumblingWindow > 0 && (d.ParallelizationFactor > 1 || len(v.Filters) > 0) {
		return v, mappingParameter("Tumbling windows cannot be combined with parallelization greater than one or filter criteria.")
	}
	v.Stream = &d
	return v, nil
}

func (c streamMappingControl) preflight(ctx context.Context, f FunctionRecord, key EventSourceMappingKey, source string, settings EventSourceMappingSettings, update *api.UpdateEventSourceMappingInput) *awswire.Error {
	parsed, err := arn.Parse(source)
	if err != nil {
		return mappingParameter("Invalid stream ARN.")
	}
	parts := strings.Split(parsed.Resource, "/")
	if c.source == "dynamodb" && (len(parts) != 4 || parts[0] != "table" || parts[1] == "" || parts[2] != "stream" || parts[3] == "") {
		return mappingParameter("EventSourceArn must identify a DynamoDB stream, not a table.")
	}
	if c.source == "kinesis" && (len(parts) != 2 && len(parts) != 4 || parts[0] != "stream" || parts[1] == "" || len(parts) == 4 && (parts[2] != "consumer" || parts[3] == "")) {
		return mappingParameter("EventSourceArn must identify a Kinesis stream or registered consumer.")
	}
	consumer, wire := c.s.openStreamConsumer(ctx, f, source)
	if wire != nil {
		return streamMappingPreflightError(wire)
	}
	defer consumer.Close()
	if _, err := consumer.Describe(ctx); err != nil {
		return streamMappingPreflightError(sourceWireError(err))
	}
	checkDestination := update == nil || update.DestinationConfig != nil || update.FunctionName != nil
	if destination := settings.Stream.OnFailure; destination != "" {
		parsed, err := arn.Parse(destination)
		if err != nil || (parsed.Service != "sqs" && parsed.Service != "sns" && parsed.Service != "s3") {
			return mappingParameter("Stream failure destinations must be SQS, SNS or S3 ARNs.")
		}
		if (parsed.Service == "sqs" || parsed.Service == "sns") && strings.HasSuffix(parsed.Resource, ".fifo") {
			return mappingParameter("FIFO SQS queues and SNS topics are not supported as stream failure destinations.")
		}
		if !checkDestination {
			return nil
		}
		if c.s.streamTargets == nil {
			return unsupported("Stream failure destinations require a destination adapter.")
		}
		if wire := c.s.streamTargets.CheckStream(ctx, f.Key, f.Role, key, destination); wire != nil {
			return streamMappingPreflightError(wire)
		}
	}
	return nil
}

func streamMappingPreflightError(wire *awswire.Error) *awswire.Error {
	if wire.StatusCode >= 500 {
		return failure("ServiceException", wire.Message, wire.StatusCode)
	}
	return mappingParameter(wire.Message)
}

func (c streamMappingControl) createTransition(v *EventSourceMappingRecord, enabled bool) {
	v.State, v.StateTransitionReason, v.LastProcessingResult = "Creating", "User action", "No records processed"
	v.TransitionState = "Disabled"
	if enabled {
		v.TransitionState = "Enabled"
	}
	v.TransitionAt = v.LastModified.Add(eventSourceMappingTransitionDelay)
}
func (c streamMappingControl) updateTransition(v *EventSourceMappingRecord, enabled *api.Enabled) {
	v.StateTransitionReason, v.TransitionState = "User action", v.State
	v.State = "Updating"
	if enabled != nil && bool(*enabled) != (v.TransitionState == "Enabled") {
		if bool(*enabled) {
			v.State, v.TransitionState = "Enabling", "Enabled"
		} else {
			v.State, v.TransitionState = "Disabling", "Disabled"
		}
	}
	v.TransitionAt = v.LastModified.Add(eventSourceMappingTransitionDelay)
}

func streamMappingConfiguration(v EventSourceMappingRecord, out *api.EventSourceMappingConfiguration) {
	d := v.Settings.Stream
	out.StartingPosition = new(api.EventSourcePosition(d.StartingPosition))
	if !d.StartingPositionTimestamp.IsZero() {
		out.StartingPositionTimestamp = new(api.Date(d.StartingPositionTimestamp))
	}
	out.ParallelizationFactor = new(api.ParallelizationFactor(d.ParallelizationFactor))
	out.MaximumRetryAttempts = new(api.MaximumRetryAttemptsEventSourceMapping(d.MaximumRetryAttempts))
	out.MaximumRecordAgeInSeconds = new(api.MaximumRecordAgeInSeconds(d.MaximumRecordAge / time.Second))
	out.BisectBatchOnFunctionError = new(api.BisectBatchOnFunctionError(d.BisectBatchOnFunctionError))
	out.TumblingWindowInSeconds = new(api.TumblingWindowInSeconds(d.TumblingWindow / time.Second))
	out.LastProcessingResult = new(api.String(v.LastProcessingResult))
	out.DestinationConfig = &api.DestinationConfig{OnFailure: &api.OnFailure{}}
	if d.OnFailure != "" {
		out.DestinationConfig.OnFailure.Destination = new(api.DestinationArn(d.OnFailure))
	}
}
