package logs

import (
	"context"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

func (s *Service) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	handler, ok := s.operations[string(d.Operation.Name)]
	if !ok {
		// TODO: Comeback implement KMS encryption, linked accounts,
		// query engines, transformations, exports and remaining Logs operations.
		return nil, unsupported("CloudWatch Logs operation requires an unimplemented dependency: " + string(d.Operation.Name))
	}
	ctx = awsapi.WithDecodedRequest(ctx, d)
	if s.apiEvents != nil && recorded(string(d.Operation.Name)) {
		var err error
		ctx, err = apievents.Reserve(ctx)
		if err != nil {
			return nil, storageFailure()
		}
	}
	out, wire := handler(ctx, d.Input)
	if wire != nil {
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err := s.record(completion, d, nil, wire); err != nil {
			return nil, storageFailure()
		}
		return nil, wire
	}
	if d.Operation.Name == "PutLogEvents" || d.Operation.Name == "PutRetentionPolicy" || d.Operation.Name == "DeleteRetentionPolicy" {
		s.jobs.Wake()
	}
	return out, nil
}

// update commits successful commands and their audit outcome together. Failed
// commands roll back to a savepoint so a caller can handle modeled errors.
// External destination preflight must finish before entering this boundary.
func (s *Service) update(ctx context.Context, fn func(Transaction) (any, *awswire.Error)) error {
	return s.repository.Attempt(ctx, func(tx Transaction) error {
		out, wire := fn(tx)
		if wire != nil {
			return wire
		}
		d, ok := awsapi.FromContext(tx.Context())
		if !ok {
			return nil
		}
		return s.record(tx.Context(), d, out, nil)
	})
}
func recorded(name string) bool {
	// Explicit documented producer set: PutLogEvents and the deprecated tag
	// mutations are not listed CloudTrail producers. Runtime logs are not audit.
	switch name {
	case "CreateLogGroup", "DeleteLogGroup", "DescribeLogGroups", "ListLogGroups", "CreateLogStream", "DeleteLogStream", "DescribeLogStreams", "GetLogEvents", "FilterLogEvents", "TagResource", "UntagResource", "ListTagsForResource", "ListTagsLogGroup", "PutRetentionPolicy", "DeleteRetentionPolicy":
		return true
	case "PutResourcePolicy", "DescribeResourcePolicies", "DeleteResourcePolicy":
		return true
	case "PutSubscriptionFilter", "DescribeSubscriptionFilters", "DeleteSubscriptionFilter":
		return true
	case "PutDestination", "PutDestinationPolicy", "DescribeDestinations", "DeleteDestination":
		return true
	case "PutMetricFilter", "DescribeMetricFilters", "DeleteMetricFilter", "TestMetricFilter":
		return true
	}
	return false
}
func (s *Service) record(ctx context.Context, d awsapi.DecodedRequest, out any, wire *awswire.Error) error {
	if s.apiEvents == nil || !recorded(string(d.Operation.Name)) {
		return nil
	}
	name := string(d.Operation.Name)
	readonly := strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List") || strings.HasPrefix(name, "Describe") || name == "FilterLogEvents" || name == "TestMetricFilter"
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readonly, Request: awsapi.DocumentProjection{}}
	if !readonly {
		p := awsapi.DocumentProjection{}
		projection.Response = &p
	}
	input := d.Input
	denied := wire != nil && (wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException")
	if name == "TestMetricFilter" || denied {
		// Native Logs omits the whole request, not just message values.
		input = nil
	} else if in, ok := input.(*api.ListLogGroupsRequest); ok && len(in.AccountIdentifiers) == 0 {
		copy := *in
		copy.AccountIdentifiers = api.AccountIds{api.AccountId(scopeFor(ctx).AccountID)}
		input = &copy
	}
	model, _ := awscatalog.LookupService("logs")
	call, err := projection.Call(model, d.Operation, input, out, wire)
	if err != nil {
		return err
	}
	if denied {
		call.ErrorCode = "AccessDenied"
	} else {
		call.APIVersion = "20140328"
		projectAuditResources(ctx, d.Input, out, wire, &call)
	}
	call.EventID = apievents.EventID(ctx)
	m := awsctx.FromContext(ctx)
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, call)
}
func (s *Service) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, wire *awswire.Error) error {
	return s.record(ctx, d, nil, wire)
}
