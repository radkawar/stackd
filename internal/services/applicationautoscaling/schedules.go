package applicationautoscaling

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/internal/awsschedule"
)

func (s *Service) putScheduledAction(ctx context.Context, tx Transaction, in *api.PutScheduledActionInput) (*api.PutScheduledActionOutput, error) {
	key, err := keyFor(ctx, value(in.ServiceNamespace), value(in.ResourceId), value(in.ScalableDimension))
	if err != nil {
		return nil, err
	}
	target, err := s.requireTarget(ctx, tx, key, "PutScheduledAction")
	if err != nil {
		return nil, err
	}
	scheduleKey := ScheduleKey{TargetKey: key, Name: value(in.ScheduledActionName)}
	record, err := tx.Schedule(scheduleKey)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, ErrNotFound) {
		now := s.clock.Now().UTC().Truncate(time.Millisecond)
		arn := "arn:" + key.Partition + ":autoscaling:" + key.Region + ":" + key.AccountID + ":scheduledAction:" + target.ID + ":resource/" + key.Namespace + "/" + key.ResourceID + ":scheduledActionName/" + scheduleKey.Name
		record = ScheduleRecord{Key: scheduleKey, Data: api.ScheduledAction{
			CreationTime: &now, ScheduledActionARN: new(api.ResourceIdMaxLen1600(arn)),
			ScheduledActionName: in.ScheduledActionName, ServiceNamespace: in.ServiceNamespace,
			ResourceId: in.ResourceId, ScalableDimension: in.ScalableDimension,
		}}
	}
	data := api.CloneScheduledAction(record.Data)
	if in.ScalableTargetAction != nil {
		action := api.CloneScalableTargetAction(*in.ScalableTargetAction)
		data.ScalableTargetAction = &action
	}
	if data.ScalableTargetAction == nil {
		return nil, invalid("ScalableTargetAction must be set")
	}
	action := data.ScalableTargetAction
	if action.MinCapacity == nil && action.MaxCapacity == nil {
		return nil, invalid("At least one of minimum capacity and maximum capacity should be provided")
	}
	if action.MinCapacity != nil && *action.MinCapacity < 0 || action.MaxCapacity != nil && *action.MaxCapacity < 0 {
		return nil, invalid("Minimum and maximum capacity must be non-negative")
	}
	if key.Namespace == "dynamodb" && (action.MinCapacity != nil && *action.MinCapacity < 1 || action.MaxCapacity != nil && *action.MaxCapacity < 1) {
		return nil, invalid("DynamoDB capacity must be at least 1")
	}
	if action.MinCapacity != nil && action.MaxCapacity != nil && *action.MinCapacity > *action.MaxCapacity {
		return nil, invalid("Minimum capacity cannot be greater than maximum capacity")
	}
	if in.Schedule != nil {
		data.Schedule = in.Schedule
	}
	if in.Timezone != nil {
		if *in.Timezone == "" {
			return nil, invalid("Timezone must not be empty")
		}
		data.Timezone = in.Timezone
	}
	// Unlike the other optional fields, omission or null clears these bounds.
	data.StartTime, data.EndTime = in.StartTime, in.EndTime
	if data.StartTime != nil && data.EndTime != nil && !data.StartTime.Before(*data.EndTime) {
		return nil, invalid("StartTime must be before EndTime")
	}
	parsed, err := awsschedule.ParseApplicationAutoScaling(value(data.Schedule), value(data.Timezone))
	if err != nil {
		return nil, invalid("Invalid schedule expression or timezone")
	}
	record.Data = api.CloneScheduledAction(data)
	record.OriginEventID = apievents.EventID(ctx)
	record.NextDue = firstScheduledDeadline(parsed, data, s.clock.Now())
	if err := tx.PutSchedule(record); err != nil {
		return nil, err
	}
	return &api.PutScheduledActionOutput{}, nil
}

func firstScheduledDeadline(parsed awsschedule.Schedule, data api.ScheduledAction, now time.Time) time.Time {
	var due time.Time
	var exists bool
	if data.StartTime != nil && !strings.HasPrefix(value(data.Schedule), "at(") {
		// A recurring action also executes at StartTime even when that instant
		// does not match its cron calendar. UTC request bounds are not wall times.
		due, exists = data.StartTime.UTC(), true
		if due.Before(now) {
			due, exists = parsed.NextAfter(due, now)
		}
	} else {
		due, exists = parsed.First(now)
	}
	if !exists || data.StartTime != nil && due.Before(*data.StartTime) || data.EndTime != nil && due.After(*data.EndTime) {
		return time.Time{}
	}
	return due
}

func (s *Service) describeScheduledActions(ctx context.Context, tx Transaction, in *api.DescribeScheduledActionsInput) (*api.DescribeScheduledActionsOutput, error) {
	namespace, resourceID, dimension := value(in.ServiceNamespace), value(in.ResourceId), value(in.ScalableDimension)
	if err := validateTargetFilter(namespace, dimension); err != nil {
		return nil, err
	}
	if dimension != "" && resourceID == "" {
		return nil, invalid("ResourceId must be specified when ScalableDimension is specified")
	}
	query := ScheduleQuery{Scope: scopeFor(ctx), Namespace: namespace, ResourceID: resourceID, Dimension: dimension, Names: listSelection(in.ScheduledActionNames)}
	page, err := newListPage[ListCursor](listPageQuery{Operation: "DescribeScheduledActions", Key: TargetKey{Scope: query.Scope, Namespace: namespace, ResourceID: resourceID, Dimension: dimension}, Names: query.Names}, in.MaxResults, in.NextToken)
	if err != nil {
		return nil, err
	}
	query.Limit, query.From = page.readLimit, page.token.Cursor
	// DescribeScheduledActions has no resource-level IAM support or action
	// condition keys; target ARN/tag authorization belongs to the mutators.
	if err := s.authorize(ctx, "DescribeScheduledActions", "*", nil); err != nil {
		return nil, err
	}
	out := &api.DescribeScheduledActionsOutput{ScheduledActions: api.ScheduledActions{}}
	if page.limit == 0 {
		return out, nil
	}
	rows, err := tx.Schedules(query)
	if err != nil {
		return nil, err
	}
	if len(rows) > page.limit {
		next := rows[page.limit].Key
		out.NextToken = page.next(listCursor(next.TargetKey, next.Name))
		rows = rows[:page.limit]
	}
	for _, row := range rows {
		out.ScheduledActions = append(out.ScheduledActions, row.Data)
	}
	return out, nil
}

func (s *Service) deleteScheduledAction(ctx context.Context, tx Transaction, in *api.DeleteScheduledActionInput) (*api.DeleteScheduledActionOutput, error) {
	key, err := keyFor(ctx, value(in.ServiceNamespace), value(in.ResourceId), value(in.ScalableDimension))
	if err != nil {
		return nil, err
	}
	if _, err := s.requireTarget(ctx, tx, key, "DeleteScheduledAction"); err != nil {
		return nil, err
	}
	scheduleKey := ScheduleKey{TargetKey: key, Name: value(in.ScheduledActionName)}
	if _, err := tx.Schedule(scheduleKey); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, failure("ObjectNotFoundException", "No scheduled action found for the specified scalable target and name")
		}
		return nil, err
	}
	if err := tx.DeleteSchedule(scheduleKey); err != nil {
		return nil, err
	}
	return &api.DeleteScheduledActionOutput{}, nil
}
