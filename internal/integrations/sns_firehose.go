package integrations

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/firehose"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/sns"
)

// SNSFirehoseRecords exposes the native SNS producer action without imposing
// batch permissions on unrelated EventBridge and Logs producers.
type SNSFirehoseRecords interface {
	PutRecordBatch(context.Context, *api.PutRecordBatchInput) (*api.PutRecordBatchOutput, *awswire.Error)
}

// SNSFirehose admits SNS-owned bytes through Firehose's ordinary authorized,
// audited producer command. Firehose owns buffering and eventual S3 delivery.
// The subscription role never falls back to the SNS service principal.
type SNSFirehose struct {
	Roles    ServiceRoles
	Firehose SNSFirehoseRecords
}

func (a SNSFirehose) Send(ctx context.Context, roleARN, endpoint string, message sns.DeliveryMessage) sns.DeliveryResult {
	if a.Firehose == nil {
		return snsFirehoseError(&awswire.Error{Code: "InternalFailure", Message: "SNS Firehose delivery is not configured.", StatusCode: 500}, message.CaptureFeedback)
	}
	target, err := arn.Parse(endpoint)
	if err != nil || target.Service != "firehose" || !strings.HasPrefix(target.Resource, "deliverystream/") {
		return snsFirehoseError(&awswire.Error{Code: "InvalidParameter", Message: "Invalid parameter: Firehose endpoint ARN", StatusCode: 400}, message.CaptureFeedback)
	}
	source := awsctx.FromContext(ctx).ServicePrincipal
	// TODO: Comeback calibrate native SNS role-session reuse and batching; one
	// retained notification currently enters one freshly authorized batch.
	credential, rejected := a.Roles.assume(ctx, source, roleARN, identity.RoleSessionSpec{SessionName: "AWS-SNS"}, "")
	if rejected != nil {
		return snsFirehoseError(rejected, message.CaptureFeedback)
	}
	ctx, rejected = serviceRoleRequestContext(ctx, credential, target.Region, "sns.amazonaws.com")
	if rejected != nil {
		return snsFirehoseError(rejected, message.CaptureFeedback)
	}
	name := api.DeliveryStreamName(strings.TrimPrefix(target.Resource, "deliverystream/"))
	out, rejected := a.Firehose.PutRecordBatch(ctx, &api.PutRecordBatchInput{DeliveryStreamName: &name, Records: api.PutRecordBatchRequestEntryList{{Data: []byte(message.Body)}}})
	if rejected != nil {
		return snsFirehoseError(rejected, message.CaptureFeedback)
	}
	record := out.RequestResponses[0]
	if record.ErrorCode != nil {
		reason := "Firehose rejected the SNS record."
		if record.ErrorMessage != nil {
			reason = string(*record.ErrorMessage)
		}
		return snsFirehoseError(&awswire.Error{Code: string(*record.ErrorCode), Message: reason, StatusCode: 500}, message.CaptureFeedback)
	}
	result := sns.DeliveryResult{StatusCode: 200}
	if message.CaptureFeedback {
		encoded, _ := json.Marshal(struct {
			RequestID string `json:"firehoseRequestId"`
		}{awsctx.FromContext(ctx).RequestID})
		result.ProviderResponse = string(encoded)
	}
	return result
}

func snsFirehoseError(rejected *awswire.Error, capture bool) sns.DeliveryResult {
	result := sns.DeliveryResult{Error: rejected, StatusCode: rejected.StatusCode}
	if rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" {
		result.StatusCode = 400
	}
	if capture {
		encoded, _ := json.Marshal(struct {
			ErrorCode    int    `json:"ErrorCode"`
			ErrorMessage string `json:"ErrorMessage"`
		}{result.StatusCode, rejected.Message})
		result.ProviderResponse = string(encoded)
	}
	return result
}
