package ebs

import (
	"context"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ebs"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
	"stackd/journal"
)

var auditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"BlockData": {Mode: awsapi.OmitField}, "KmsKeyArn": {Mode: awsapi.RedactValueField, Redaction: "HIDDEN_DUE_TO_SECURITY_REASONS"}}}
var auditResponse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"BlockData": {Mode: awsapi.OmitField}, "KmsKeyArn": {Mode: awsapi.RedactValueField, Redaction: "HIDDEN_DUE_TO_SECURITY_REASONS"}, "StartTime": {TimeLayout: time.RFC3339}}}

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ebs")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	category := journal.CategoryData
	if action == "StartSnapshot" || action == "CompleteSnapshot" {
		category = journal.CategoryManagement
	}
	readOnly := action == "ListSnapshotBlocks" || action == "ListChangedBlocks" || action == "GetSnapshotBlock"
	projection := apievents.Projection{Category: category, ReadOnly: readOnly, Request: auditRequest}
	if !readOnly {
		projection.Response = &auditResponse
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	// Native API authorization denials suppress request and response documents,
	// but retain resource attribution. Validation and KMS dependency failures
	// retain their normal request projection.
	if rejected != nil && rejected.Code == "AccessDeniedException" {
		call.RequestParameters, call.ResponseElements = nil, nil
		call.ErrorCode = "AccessDenied"
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	ids := []string{}
	switch request := in.(type) {
	case *api.StartSnapshotRequest:
		if response, ok := out.(*api.StartSnapshotResponse); ok && response != nil {
			ids = append(ids, value(response.SnapshotId))
		}
		if id := value(request.ParentSnapshotId); id != "" {
			call.EventResources = append(call.EventResources, journal.APIEventResource{Type: "AWS::EC2::Snapshot", ARN: snapshotARN(SnapshotKey{scope, id}), AccountID: scope.AccountID})
		}
	case *api.CompleteSnapshotRequest:
		ids = append(ids, value(request.SnapshotId))
	case *api.PutSnapshotBlockRequest:
		ids = append(ids, value(request.SnapshotId))
	case *api.GetSnapshotBlockRequest:
		ids = append(ids, value(request.SnapshotId))
	case *api.ListSnapshotBlocksRequest:
		ids = append(ids, value(request.SnapshotId))
	case *api.ListChangedBlocksRequest:
		ids = append(ids, value(request.FirstSnapshotId), value(request.SecondSnapshotId))
	}
	for _, id := range ids {
		if id == "" {
			continue
		}
		if category == journal.CategoryData || ec2.HasSharedSnapshotOwner(ctx) {
			call.EventResources = append(call.EventResources, journal.APIEventResource{Type: "AWS::EC2::Snapshot", ARN: snapshotARN(SnapshotKey{scope, id}), AccountID: scope.AccountID})
		}
		if category == journal.CategoryManagement {
			call.Resources = append(call.Resources, journal.APIResource{Type: "AWS::EC2::Snapshot", Name: id})
		}
	}
	envelope := journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}
	if action != "ListSnapshotBlocks" && action != "ListChangedBlocks" && call.ErrorCode != "AccessDenied" {
		return ec2.RecordSnapshotAudit(ctx, s.recorder, envelope, call, true)
	}
	return s.recorder.Record(ctx, envelope, call)
}

func (s *Service) observeSnapshot(ctx context.Context, v SnapshotRecord) {
	share, _ := snapshotShare(v, scopeFor(ctx).AccountID)
	ec2.ObserveSnapshotOwner(ctx, v.Key.AccountID, !v.Deleted && (v.Public || share.Readable))
}
