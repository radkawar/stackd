package firehose

import (
	"context"
	"encoding/json"
	"errors"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

var auditPutRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Record":  {Mode: awsapi.OmitField},
	"Records": {Mode: awsapi.OmitField},
}}

func auditProjection(action string) (apievents.Projection, bool) {
	p := apievents.Projection{Category: journal.CategoryManagement}
	switch action {
	case "CreateDeliveryStream":
		p.Response = &awsapi.DocumentProjection{}
	case "DescribeDeliveryStream", "ListDeliveryStreams", "ListTagsForDeliveryStream":
		p.ReadOnly = true
	case "DeleteDeliveryStream", "UpdateDestination", "TagDeliveryStream", "UntagDeliveryStream":
	case "StartDeliveryStreamEncryption", "StopDeliveryStreamEncryption":
		// These are documented CloudTrail management operations, but the
		// frontend currently rejects them. Record the actual rejection, never
		// an invented successful encryption response.
	case "PutRecord", "PutRecordBatch":
		// Native S3-delivered events classify both producer writes as
		// read-only Data events. Neither records nor record IDs are logged.
		// The CloudTrail data-event resource table lists this resource type:
		// https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
		p.Category, p.ReadOnly, p.Request = journal.CategoryData, true, auditPutRequest
	default:
		return apievents.Projection{}, false
	}
	return p, true
}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	projection, supported := auditProjection(action)
	if !supported {
		return nil
	}
	model, ok := awscatalog.LookupService("firehose")
	if !ok {
		return errors.New("firehose audit service metadata is missing")
	}
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	// All 150 matched controls have an empty lookup resource index. Successful
	// controls omit embedded resources; rejected controls and all nine native
	// S3-delivered producer events include the selected delivery stream once.
	if rejected != nil || call.Category == journal.CategoryData {
		// Read only the generated, sanitized projection, before nulling the
		// admission-error parameters. A malformed body has no bound selector.
		var request struct {
			DeliveryStreamName string `json:"deliveryStreamName"`
		}
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
		if request.DeliveryStreamName != "" {
			key := StreamKey{Scope: scope, Name: request.DeliveryStreamName}
			call.EventResources = []journal.APIEventResource{{
				AccountID: scope.AccountID,
				Type:      "AWS::KinesisFirehose::DeliveryStream",
				ARN:       key.ARN(),
			}}
		}
	}
	if rejected != nil {
		switch rejected.Code {
		case "AccessDenied", "AccessDeniedException":
			call.ErrorCode = "AccessDenied"
			call.RequestParameters = json.RawMessage("null")
		case "ValidationException", "SerializationException":
			call.RequestParameters = json.RawMessage("null")
		}
	}
	// runCommand owns the reservation and commit/rollback boundary. The
	// shared recorder supplies verified caller, request and causal identity.
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
