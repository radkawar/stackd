package integrations

import (
	"context"

	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/eventbridge/inputtransform"
)

// KinesisRecordWriter enters the real stream command under the assumed target
// role, preserving the stream's IAM, KMS, capacity and API audit boundaries.
type KinesisRecordWriter interface {
	PutRecord(context.Context, *kinesisapi.PutRecordInput) (*kinesisapi.PutRecordOutput, *awswire.Error)
}

func (a EventBridgeTargets) sendKinesis(ctx context.Context, request eventbridge.DeliveryRequest, body string) *awswire.Error {
	if a.Kinesis == nil {
		return &awswire.Error{Code: "InternalFailure", Message: "Kinesis target delivery is not configured.", StatusCode: 500}
	}
	// Native delivery prefixes an opaque UUID with the event ID. Retain the
	// delivery identity as that suffix so retries and restarts keep routing.
	key := request.Event.WireID + "_" + request.Delivery.ID
	if p := request.Delivery.KinesisParameters; p != nil {
		if p.PartitionKeyPath == nil {
			return &awswire.Error{Code: "InternalFailure", Message: "Invalid retained Kinesis target parameters.", StatusCode: 500}
		}
		path := string(*p.PartitionKeyPath)
		projection, err := inputtransform.Compile(inputtransform.Definition{InputPath: &path})
		if err != nil {
			return &awswire.Error{Code: "InternalFailure", Message: "Invalid retained Kinesis partition key path.", StatusCode: 500}
		}
		// Dynamic target parameters select from the original event, independently
		// of Input, InputPath or InputTransformer applied to the record's data.
		original, err := (eventbridge.DeliveryRequest{Event: request.Event}).Payload()
		if err != nil {
			return &awswire.Error{Code: "InternalFailure", Message: "Invalid retained EventBridge event.", StatusCode: 500}
		}
		selected, err := projection.Apply([]byte(original), inputtransform.Context{})
		if err != nil {
			return &awswire.Error{Code: "InternalFailure", Message: "Unable to select retained Kinesis partition key.", StatusCode: 500}
		}
		// Native Kinesis targets use the JSON projection itself as the key:
		// strings retain quotes, scalars/containers are compact JSON, and a
		// missing or null path produces {}. See the owned native capture.
		key = string(selected)
	}
	stream, partition := kinesisapi.StreamARN(request.Delivery.TargetARN), kinesisapi.PartitionKey(key)
	_, rejected := a.Kinesis.PutRecord(ctx, &kinesisapi.PutRecordInput{StreamARN: &stream, PartitionKey: &partition, Data: kinesisapi.Data(body)})
	return rejected
}
