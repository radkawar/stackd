package integrations

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/firehose"
	"stackd/internal/awswire"
)

// FirehoseRecordWriter is the ordinary authorized producer command shared by
// EventBridge targets and Logs subscriptions. Firehose owns retained S3 delivery.
type FirehoseRecordWriter interface {
	PutRecord(context.Context, *api.PutRecordInput) (*api.PutRecordOutput, *awswire.Error)
}

func (a EventBridgeTargets) sendFirehose(ctx context.Context, target arn.ARN, body string) *awswire.Error {
	if a.Firehose == nil {
		return &awswire.Error{Code: "InternalFailure", Message: "Firehose target delivery is not configured.", StatusCode: 500}
	}
	name := api.DeliveryStreamName(strings.TrimPrefix(target.Resource, "deliverystream/"))
	_, rejected := a.Firehose.PutRecord(ctx, &api.PutRecordInput{DeliveryStreamName: &name, Record: &api.Record{Data: []byte(body)}})
	return rejected
}
