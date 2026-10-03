package scheduler

import (
	"context"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/scheduler"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// lifecycle_success.json contains exact-request-ID S3-delivered native records.
// Scheduler omits payload and tag values entirely, rather than writing a mask.
var schedulerAuditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Target.Input": {Mode: awsapi.OmitField},
	"Tags":         {Mode: awsapi.OmitField},
	"TagKeys":      {Mode: awsapi.OmitField},
	"StartDate":    {TimeLayout: time.RFC3339},
	"EndDate":      {TimeLayout: time.RFC3339},
}}

func (s *Service) recordCall(ctx context.Context, action string, input, output any, rejected *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("scheduler")
	op, _ := model.Operation(action)
	projection := apievents.Projection{Category: journal.CategoryManagement, Request: schedulerAuditRequest}
	switch action {
	case "GetSchedule", "GetScheduleGroup", "ListSchedules", "ListScheduleGroups", "ListTagsForResource":
		projection.ReadOnly = true
	case "CreateSchedule", "UpdateSchedule", "CreateScheduleGroup":
		projection.Response = &awsapi.DocumentProjection{}
	}
	// Native ListSchedules publishes its effective default page size. Do not
	// mutate the DTO being used by the caller or other request observers.
	if in, ok := input.(*api.ListSchedulesInput); ok && in != nil && in.MaxResults == nil {
		detached := *in
		detached.MaxResults = new(api.MaxResults(100))
		input = &detached
	}
	call, err := projection.Call(model, op, input, output, rejected)
	if err != nil {
		return err
	}
	// Captured Scheduler records do not contain apiVersion.
	scope := scopeFor(ctx)
	return s.apiEvents.Record(ctx, journal.Envelope{
		At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region,
	}, call)
}

func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
