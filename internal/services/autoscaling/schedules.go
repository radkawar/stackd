package autoscaling

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awswire"
)

func registerSchedules(s *Service) {
	register(s, "PutScheduledUpdateGroupAction", s.putScheduledUpdateGroupAction)
	register(s, "DescribeScheduledActions", s.describeScheduledActions)
	register(s, "DeleteScheduledAction", s.deleteScheduledAction)
	register(s, "BatchPutScheduledUpdateGroupAction", s.batchPutScheduledUpdateGroupAction)
	register(s, "BatchDeleteScheduledAction", s.batchDeleteScheduledAction)
}

func (s *Service) putScheduledUpdateGroupAction(ctx context.Context, tx Transaction, in *api.PutScheduledUpdateGroupActionInput) (*api.PutScheduledUpdateGroupActionOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "PutScheduledUpdateGroupAction")
	if err != nil {
		return nil, err
	}
	if err = s.storeScheduledAction(ctx, tx, g, in); err != nil {
		return nil, err
	}
	return &api.PutScheduledUpdateGroupActionOutput{}, nil
}

func (s *Service) storeScheduledAction(ctx context.Context, tx Transaction, g GroupRecord, in *api.PutScheduledUpdateGroupActionInput) error {
	name := value(in.ScheduledActionName)
	if name == "" || len(name) > 255 {
		return invalid("ScheduledActionName is required and must not exceed 255 characters")
	}
	key := ScheduleKey{GroupKey: g.Key, Name: name}
	record, err := tx.Schedule(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if errors.Is(err, ErrNotFound) {
		rows, err := tx.Schedules(g.Key)
		if err != nil {
			return err
		}
		if len(rows) >= 125 {
			return failure("LimitExceeded", "You may not create more than 125 scheduled actions for an Auto Scaling group")
		}
		arn := "arn:" + g.Key.Partition + ":autoscaling:" + g.Key.Region + ":" + g.Key.AccountID + ":scheduledUpdateGroupAction:" + uuid.NewString() + ":autoScalingGroupName/" + g.Key.Name + ":scheduledActionName/" + name
		record = ScheduleRecord{Key: key, GroupID: g.ID, Data: api.ScheduledUpdateGroupAction{AutoScalingGroupName: new(api.XmlStringMaxLen255(g.Key.Name)), ScheduledActionName: in.ScheduledActionName, ScheduledActionARN: new(api.ResourceName(arn))}}
	}
	data := record.Data
	if in.MinSize != nil {
		data.MinSize = in.MinSize
	}
	if in.MaxSize != nil {
		data.MaxSize = in.MaxSize
	}
	if in.DesiredCapacity != nil {
		data.DesiredCapacity = in.DesiredCapacity
	}
	if data.MinSize == nil && data.MaxSize == nil && data.DesiredCapacity == nil {
		return invalid("At least one of MinSize, MaxSize, or DesiredCapacity must be specified")
	}
	if data.MinSize != nil && *data.MinSize < 0 || data.MaxSize != nil && *data.MaxSize < 0 || data.DesiredCapacity != nil && *data.DesiredCapacity < 0 {
		return invalid("Scheduled capacities must not be negative")
	}
	if data.MinSize != nil && data.MaxSize != nil && int32(*data.MinSize) > int32(*data.MaxSize) {
		return invalid("MinSize must not exceed MaxSize")
	}
	if data.DesiredCapacity != nil && (data.MinSize != nil && int32(*data.DesiredCapacity) < int32(*data.MinSize) || data.MaxSize != nil && int32(*data.DesiredCapacity) > int32(*data.MaxSize)) {
		return invalid("DesiredCapacity must be between MinSize and MaxSize")
	}
	if in.StartTime != nil && in.Time != nil && !in.StartTime.Equal(*in.Time) {
		return invalid("Time and StartTime must have the same value when both are specified")
	}
	if in.Recurrence != nil {
		data.Recurrence = in.Recurrence
	}
	if in.TimeZone != nil {
		if *in.TimeZone == "" {
			return invalid("TimeZone must not be empty")
		}
		data.TimeZone = in.TimeZone
	}
	if in.StartTime != nil {
		data.StartTime = new(in.StartTime.UTC().Truncate(time.Second))
	} else if in.Time != nil {
		data.StartTime = new(in.Time.UTC().Truncate(time.Second))
	}
	if in.EndTime != nil {
		data.EndTime = new(in.EndTime.UTC().Truncate(time.Second))
	}
	now := s.clock.Now()
	if (in.StartTime != nil || in.Time != nil) && data.StartTime.Before(now.Truncate(time.Second)) {
		return invalid("StartTime must not be in the past")
	}
	if data.EndTime != nil && (data.EndTime.Before(now) || data.StartTime != nil && !data.EndTime.After(*data.StartTime)) {
		return invalid("EndTime must be in the future and after StartTime")
	}
	due := time.Time{}
	if value(data.Recurrence) != "" {
		parsed, err := parseRecurrence(value(data.Recurrence), value(data.TimeZone))
		if err != nil {
			return err
		}
		if data.StartTime != nil && !data.StartTime.Before(now) {
			due = *data.StartTime
		} else {
			due, _ = parsed.next(now)
		}
	} else {
		if data.StartTime == nil {
			return invalid("StartTime or Recurrence must be specified")
		}
		if data.TimeZone != nil {
			return invalid("TimeZone requires Recurrence")
		}
		due = *data.StartTime
	}
	if due.IsZero() || data.EndTime != nil && due.After(*data.EndTime) {
		return invalid("The schedule has no future occurrences")
	}
	data.Time = data.StartTime
	record.Data = api.CloneScheduledUpdateGroupAction(data)
	record.NextDue = due
	record.OriginEventID = apievents.EventID(ctx)
	return tx.PutSchedule(record)
}

func (s *Service) describeScheduledActions(ctx context.Context, tx Transaction, in *api.DescribeScheduledActionsInput) (*api.DescribeScheduledActionsOutput, error) {
	if err := s.authorize(ctx, "DescribeScheduledActions", "*", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	names := listSelection(in.ScheduledActionNames)
	start, end := in.StartTime, in.EndTime
	if len(names) > 0 {
		start, end = nil, nil
	}
	if start != nil && end != nil && end.Before(*start) {
		return nil, invalid("EndTime must not precede StartTime")
	}
	groups, err := tx.Groups(GroupQuery{Scope: scope})
	if err != nil {
		return nil, err
	}
	rows := []ScheduleRecord{}
	now := s.clock.Now()
	for _, g := range groups {
		if value(in.AutoScalingGroupName) != "" && g.Key.Name != value(in.AutoScalingGroupName) {
			continue
		}
		records, err := tx.Schedules(g.Key)
		if err != nil {
			return nil, err
		}
		for _, r := range records {
			if r.GroupID != g.ID || len(names) > 0 && !slices.Contains(names, r.Key.Name) {
				continue
			}
			if r.Data.EndTime != nil && now.After(*r.Data.EndTime) {
				continue
			}
			if start != nil && r.Data.StartTime != nil && r.Data.StartTime.Before(*start) || end != nil && r.Data.StartTime != nil && r.Data.StartTime.After(*end) {
				continue
			}
			rows = append(rows, r)
		}
	}
	rows, next, err := pageRows(scope, "DescribeScheduledActions", []any{value(in.AutoScalingGroupName), names, start, end}, in.MaxRecords, in.NextToken, rows, func(r ScheduleRecord) string { return r.Key.GroupKey.Name + "\x00" + r.Key.Name })
	if err != nil {
		return nil, err
	}
	out := &api.DescribeScheduledActionsOutput{NextToken: next, ScheduledUpdateGroupActions: api.ScheduledUpdateGroupActions{}}
	for _, r := range rows {
		out.ScheduledUpdateGroupActions = append(out.ScheduledUpdateGroupActions, r.Data)
	}
	return out, nil
}

func (s *Service) deleteScheduledAction(ctx context.Context, tx Transaction, in *api.DeleteScheduledActionInput) (*api.DeleteScheduledActionOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "DeleteScheduledAction")
	if err != nil {
		return nil, err
	}
	if err = deleteSchedule(tx, g, value(in.ScheduledActionName)); err != nil {
		return nil, err
	}
	return &api.DeleteScheduledActionOutput{}, nil
}
func deleteSchedule(tx Transaction, g GroupRecord, name string) error {
	key := ScheduleKey{GroupKey: g.Key, Name: name}
	record, err := tx.Schedule(key)
	if errors.Is(err, ErrNotFound) || err == nil && record.GroupID != g.ID {
		return invalid("Scheduled action name not found")
	}
	if err != nil {
		return err
	}
	return tx.DeleteSchedule(key)
}

func batchScheduleFailure(name *api.XmlStringMaxLen255, err error) (api.FailedScheduledUpdateGroupActionRequest, error) {
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || rejected.StatusCode >= 500 {
		return api.FailedScheduledUpdateGroupActionRequest{}, err
	}
	return api.FailedScheduledUpdateGroupActionRequest{ScheduledActionName: name, ErrorCode: new(api.XmlStringMaxLen64(rejected.Code)), ErrorMessage: new(api.XmlString(rejected.Message))}, nil
}
func (s *Service) batchPutScheduledUpdateGroupAction(ctx context.Context, tx Transaction, in *api.BatchPutScheduledUpdateGroupActionInput) (*api.BatchPutScheduledUpdateGroupActionOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "BatchPutScheduledUpdateGroupAction")
	if err != nil {
		return nil, err
	}
	if len(in.ScheduledUpdateGroupActions) < 1 || len(in.ScheduledUpdateGroupActions) > 50 {
		return nil, invalid("A batch must contain between 1 and 50 scheduled actions")
	}
	seen := map[string]bool{}
	for _, a := range in.ScheduledUpdateGroupActions {
		name := value(a.ScheduledActionName)
		if seen[name] {
			return nil, invalid("ScheduledActionName must be unique within a batch")
		}
		seen[name] = true
	}
	out := &api.BatchPutScheduledUpdateGroupActionOutput{FailedScheduledUpdateGroupActions: api.FailedScheduledUpdateGroupActionRequests{}}
	for _, a := range in.ScheduledUpdateGroupActions {
		err = s.repository.Attempt(tx.Context(), func(child Transaction) error {
			return s.storeScheduledAction(ctx, child, g, &api.PutScheduledUpdateGroupActionInput{AutoScalingGroupName: in.AutoScalingGroupName, ScheduledActionName: a.ScheduledActionName, MinSize: a.MinSize, MaxSize: a.MaxSize, DesiredCapacity: a.DesiredCapacity, Recurrence: a.Recurrence, StartTime: a.StartTime, EndTime: a.EndTime, TimeZone: a.TimeZone})
		})
		if err != nil {
			failed, fatal := batchScheduleFailure(a.ScheduledActionName, err)
			if fatal != nil {
				return nil, fatal
			}
			out.FailedScheduledUpdateGroupActions = append(out.FailedScheduledUpdateGroupActions, failed)
		}
	}
	return out, nil
}
func (s *Service) batchDeleteScheduledAction(ctx context.Context, tx Transaction, in *api.BatchDeleteScheduledActionInput) (*api.BatchDeleteScheduledActionOutput, error) {
	g, err := s.loadGroup(ctx, tx, value(in.AutoScalingGroupName), "BatchDeleteScheduledAction")
	if err != nil {
		return nil, err
	}
	if len(in.ScheduledActionNames) < 1 || len(in.ScheduledActionNames) > 50 {
		return nil, invalid("A batch must contain between 1 and 50 scheduled action names")
	}
	out := &api.BatchDeleteScheduledActionOutput{FailedScheduledActions: api.FailedScheduledUpdateGroupActionRequests{}}
	for _, name := range in.ScheduledActionNames {
		err = deleteSchedule(tx, g, string(name))
		if err != nil {
			failed, fatal := batchScheduleFailure(new(api.XmlStringMaxLen255(name)), err)
			if fatal != nil {
				return nil, fatal
			}
			out.FailedScheduledActions = append(out.FailedScheduledActions, failed)
		}
	}
	return out, nil
}
