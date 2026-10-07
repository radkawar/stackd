package lambda

import (
	"context"
	"testing"

	kinesisapi "stackd/internal/awsapi/kinesis"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// Admission needs only an authorized source description, not a running log or
// customer runtime. Destination existence and permissions use the real SQS owner.
type destinationAdmissionSource struct {
	KinesisConsumer
	arn string
}

func (s destinationAdmissionSource) Open(context.Context, FunctionKey, string, string) (KinesisConsumer, *awswire.Error) {
	return s, nil
}

func (s destinationAdmissionSource) Check(context.Context) (*kinesisapi.StreamDescription, *awswire.Error) {
	return &kinesisapi.StreamDescription{StreamARN: new(kinesisapi.StreamARN(s.arn)), RetentionPeriodHours: new(kinesisapi.RetentionPeriodHours(24))}, nil
}

func (s destinationAdmissionSource) Describe(context.Context, *kinesisapi.DescribeStreamInput) (*kinesisapi.DescribeStreamOutput, *awswire.Error) {
	description, wire := s.Check(context.Background())
	return &kinesisapi.DescribeStreamOutput{StreamDescription: description}, wire
}

func TestStreamFailureDestinationRejectsFIFOWithoutCommittingMapping(t *testing.T) {
	s, manual, _, ctx, function, mapping := pollingFixture(t, nil)
	fifo := pollingQueueFixture(t, ctx, manual, "fifo-failures", true)
	standard := pollingQueueFixture(t, ctx, manual, "standard-failures", false)
	s.kinesis = destinationAdmissionSource{arn: mapping.EventSourceARN}
	s.streamTargets = standard
	for _, destination := range []string{fifo.arn, "arn:aws:sns:us-east-1:111111111111:fifo-failures.fifo"} {
		input := &api.CreateEventSourceMappingInput{
			FunctionName:      new(api.NamespacedFunctionName(function.Key.Name)),
			EventSourceArn:    new(api.Arn(mapping.EventSourceARN)),
			StartingPosition:  new(api.EventSourcePositionTRIM_HORIZON),
			DestinationConfig: &api.DestinationConfig{OnFailure: &api.OnFailure{Destination: new(api.DestinationArn(destination))}},
		}
		if output, wire := s.createEventSourceMapping(ctx, input); output != nil || wire == nil || wire.Code != "InvalidParameterValueException" {
			t.Fatalf("FIFO destination reached mapping creation: output=%+v wire=%v", output, wire)
		}
		update := &api.UpdateEventSourceMappingInput{UUID: new(api.UUIDString(mapping.Key.UUID)), DestinationConfig: input.DestinationConfig}
		if output, wire := s.updateEventSourceMapping(ctx, update); output != nil || wire == nil || wire.Code != "InvalidParameterValueException" {
			t.Fatalf("FIFO destination reached mapping update: output=%+v wire=%v", output, wire)
		}
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		rows, err := r.AllEventSourceMappings()
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Key != mapping.Key || rows[0].Version != mapping.Version || rows[0].Settings.Stream.OnFailure != "" {
			t.Fatalf("rejected FIFO destination changed retained mappings: %+v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	input := &api.UpdateEventSourceMappingInput{
		UUID:              new(api.UUIDString(mapping.Key.UUID)),
		DestinationConfig: &api.DestinationConfig{OnFailure: &api.OnFailure{Destination: new(api.DestinationArn(standard.arn))}},
	}
	if _, wire := s.updateEventSourceMapping(ctx, input); wire != nil {
		t.Fatal(wire)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		retained, err := r.EventSourceMapping(mapping.Key)
		if err != nil {
			return err
		}
		if retained.Settings.Stream.OnFailure != standard.arn || retained.EventSourceARN != mapping.EventSourceARN || retained.Function.FunctionKey != function.Key {
			t.Fatalf("standard destination update changed source/function identity or failed to persist: %+v", retained)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStreamFailureDestinationValidationDoesNotReauthorizeUntouchedStandardDestination(t *testing.T) {
	s, _, _, ctx, function, mapping := pollingFixture(t, nil)
	s.kinesis = destinationAdmissionSource{arn: mapping.EventSourceARN}
	control := streamMappingControl{s: s, source: "kinesis"}
	// No target adapter is installed: an untouched, structurally valid destination
	// must not acquire a new IAM preflight on an unrelated mapping update.
	mapping.Settings.Stream.OnFailure = "arn:aws:sqs:us-east-1:111111111111:standard-failures"
	update := &api.UpdateEventSourceMappingInput{BatchSize: new(api.BatchSize(100))}
	if wire := control.preflight(ctx, function, mapping.Key, mapping.EventSourceARN, mapping.Settings, update); wire != nil {
		t.Fatalf("unrelated update reauthorized a standard destination: %v", wire)
	}
	mapping.Settings.Stream.OnFailure += ".fifo"
	if wire := control.preflight(ctx, function, mapping.Key, mapping.EventSourceARN, mapping.Settings, update); wire == nil || wire.Code != "InvalidParameterValueException" {
		t.Fatalf("unrelated update preserved an inadmissible FIFO destination: %v", wire)
	}
}
