package cloudtrail

import (
	"context"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// execute reserves causal identity before commands call other services. Those
// effects commit independently; update owns each trail mutation's atomic outcome.
func (s *Service) execute(ctx context.Context, decoded awsapi.DecodedRequest, handler func(context.Context, any) (any, *awswire.Error)) (any, *awswire.Error) {
	if s.apiEvents == nil {
		return handler(ctx, decoded.Input)
	}
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, storageFailure()
	}
	out, wire := handler(ctx, decoded.Input)
	if wire != nil || readOnlyOperation(decoded.Operation.Name) {
		if err := s.record(ctx, decoded, out, wire); err != nil {
			return nil, wireError(err)
		}
	}
	return out, wire
}

// update commits the actual API output with the trail transition. It deliberately
// does not wrap external destination calls in a transaction belonging to CloudTrail.
func (s *Service) update(ctx context.Context, out any, fn func(Transaction) error) error {
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := fn(tx); err != nil {
			return err
		}
		if s.apiEvents == nil {
			return nil
		}
		decoded, ok := awsapi.FromContext(tx.Context())
		if !ok {
			return nil
		}
		return s.record(tx.Context(), decoded, out, nil)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return err
}

func readOnlyOperation(name awscatalog.OperationName) bool {
	// CloudTrail's Smithy operations lack readonly traits; classification is
	// service behavior, confirmed by the native management-event fixtures.
	switch name {
	case "GetTrail", "GetTrailStatus", "GetEventSelectors", "DescribeTrails", "ListTrails", "ListTags", "LookupEvents", "ListPublicKeys":
		return true
	default:
		return false
	}
}
func (s *Service) record(ctx context.Context, decoded awsapi.DecodedRequest, out any, wire *awswire.Error) error {
	model, _ := awscatalog.LookupService("cloudtrail")
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readOnlyOperation(decoded.Operation.Name), Request: auditProjection}
	if !projection.ReadOnly {
		projection.Response = &auditProjection
	}
	call, err := projection.Call(model, decoded.Operation, decoded.Input, out, wire)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	m := awsctx.FromContext(ctx)
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, call)
}

var auditProjection = awsapi.DocumentProjection{
	Fields: map[string]awsapi.FieldProjection{
		"StartTime": {TimeLayout: time.RFC3339},
		"EndTime":   {TimeLayout: time.RFC3339},
	},
}

// RecordRequestError observes a known implemented API rejected before its command
// transaction. Excluded Lake and unimplemented operations are not native outcomes.
func (s *Service) RecordRequestError(ctx context.Context, decoded awsapi.DecodedRequest, failure *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	if _, implemented := s.operations[string(decoded.Operation.Name)]; !implemented {
		return nil
	}
	return s.record(ctx, decoded, nil, failure)
}
