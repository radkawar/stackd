package cloudwatch

import (
	"database/sql"
	"errors"
	"slices"
	"time"

	"stackd/internal/scheduler"
	domain "stackd/storage/cloudwatch"
	"stackd/storage/sqlite/cloudwatch/internal/sqlcgen"
)

func alarmString(v *string) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *v, Valid: true}
}
func alarmInt(v *int32) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}
func alarmBool(v *bool) sql.NullBool {
	if v == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *v, Valid: true}
}
func alarmTime(v *time.Time) sql.NullTime {
	if v == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: v.UTC(), Valid: true}
}
func alarmStringPointer(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}
func alarmIntPointer(v sql.NullInt64) *int32 {
	if !v.Valid {
		return nil
	}
	value := int32(v.Int64)
	return &value
}
func alarmBoolPointer(v sql.NullBool) *bool {
	if !v.Valid {
		return nil
	}
	return &v.Bool
}
func alarmTimePointer(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	return &v.Time
}

func (r reader) Alarm(key domain.AlarmKey) (domain.AlarmRecord, error) {
	row, err := r.q.GetAlarm(r.ctx, sqlcgen.GetAlarmParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AlarmRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AlarmRecord{}, err
	}
	return r.alarm(row)
}

func (r reader) AlarmByID(id string) (domain.AlarmRecord, error) {
	row, err := r.q.GetAlarmByID(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AlarmRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AlarmRecord{}, err
	}
	return r.alarm(row)
}

func (r reader) alarm(row sqlcgen.CloudwatchAlarm) (domain.AlarmRecord, error) {
	out := domain.AlarmRecord{
		Key: domain.AlarmKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		ID:  row.ID, Version: uint64(row.Version), Created: row.Created, Updated: row.Updated,
		Description: alarmStringPointer(row.Description), ActionsEnabled: row.ActionsEnabled,
		State:          domain.AlarmState{Value: row.StateValue, Reason: alarmStringPointer(row.StateReason), ReasonData: row.StateReasonData, Updated: row.StateUpdated, Transitioned: row.StateTransitioned, Origin: domain.AlarmOrigin{EventID: row.StateEventID, RequestID: row.StateRequestID}},
		NextEvaluation: alarmTimePointer(row.NextEvaluation), SuppressionPhase: row.SuppressionPhase, SuppressionReason: row.SuppressionReason, SuppressionUntil: alarmTimePointer(row.SuppressionUntil),
		EvaluationOrigin: domain.AlarmOrigin{EventID: row.EvaluationEventID, RequestID: row.EvaluationRequestID},
	}
	targets, err := r.q.ListAlarmTargets(r.ctx, row.ID)
	if err != nil {
		return domain.AlarmRecord{}, err
	}
	for _, target := range targets {
		switch target.State {
		case "ALARM":
			out.Actions.Alarm = append(out.Actions.Alarm, target.Arn)
		case "OK":
			out.Actions.OK = append(out.Actions.OK, target.Arn)
		case "INSUFFICIENT_DATA":
			out.Actions.InsufficientData = append(out.Actions.InsufficientData, target.Arn)
		}
	}
	tags, err := r.q.ListAlarmTags(r.ctx, row.ID)
	if err != nil {
		return domain.AlarmRecord{}, err
	}
	if len(tags) != 0 {
		out.Tags = make(map[string]string, len(tags))
		for _, tag := range tags {
			out.Tags[tag.Key] = tag.Value
		}
	}
	if row.AlarmType == "CompositeAlarm" {
		config, err := r.q.GetAlarmCompositeConfig(r.ctx, row.ID)
		if err != nil {
			return domain.AlarmRecord{}, err
		}
		children, err := r.q.ListAlarmChildren(r.ctx, row.ID)
		if err != nil {
			return domain.AlarmRecord{}, err
		}
		out.Composite = &domain.CompositeAlarmConfig{Rule: config.Rule, Children: children, Suppressor: config.Suppressor, WaitPeriod: int32(config.WaitPeriod), ExtensionPeriod: int32(config.ExtensionPeriod)}
	} else {
		config, err := r.q.GetAlarmMetricConfig(r.ctx, row.ID)
		if err != nil {
			return domain.AlarmRecord{}, err
		}
		out.Metric = &domain.MetricAlarmConfig{QueryID: config.QueryID, Comparison: config.Comparison, Threshold: config.Threshold, EvaluationPeriods: int32(config.EvaluationPeriods), DatapointsToAlarm: alarmIntPointer(config.DatapointsToAlarm), TreatMissingData: config.TreatMissingData, LowSampleCount: config.LowSampleCount}
		queries, err := r.q.ListAlarmQueries(r.ctx, row.ID)
		if err != nil {
			return domain.AlarmRecord{}, err
		}
		if len(queries) != 0 {
			out.Metric.Queries = make([]domain.AlarmMetricQuery, len(queries))
		}
		for i, query := range queries {
			out.Metric.Queries[i] = domain.AlarmMetricQuery{ID: query.QueryID, Expression: query.Expression, AccountID: query.AccountID, Label: alarmStringPointer(query.Label), Period: alarmIntPointer(query.Period), ReturnData: alarmBoolPointer(query.ReturnData)}
		}
		stats, err := r.q.ListAlarmMetricStats(r.ctx, row.ID)
		if err != nil {
			return domain.AlarmRecord{}, err
		}
		dimensions, err := r.q.ListAlarmDimensions(r.ctx, row.ID)
		if err != nil {
			return domain.AlarmRecord{}, err
		}
		dimensionIndex := 0
		for _, stat := range stats {
			metric := &domain.AlarmMetricStat{
				Key:    domain.MetricKey{Scope: domain.Scope{Partition: stat.Partition, AccountID: stat.AccountID, Region: stat.Region}, Namespace: stat.Namespace, Name: stat.Name, Dimensions: stat.Dimensions},
				Period: int32(stat.Period), Statistic: stat.Statistic, Unit: stat.Unit,
			}
			for dimensionIndex < len(dimensions) && dimensions[dimensionIndex].MetricPosition == stat.Position {
				dimension := dimensions[dimensionIndex]
				metric.Dimensions = append(metric.Dimensions, domain.Dimension{Name: dimension.Name, Value: dimension.Value})
				dimensionIndex++
			}
			if stat.Position == -1 {
				out.Metric.Metric = metric
			} else {
				for i, query := range queries {
					if query.Position == stat.Position {
						out.Metric.Queries[i].Metric = metric
						break
					}
				}
			}
		}
	}
	return out, nil
}

func (r reader) Alarms(q domain.AlarmQuery) ([]domain.AlarmRecord, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]domain.AlarmRecord, 0, min(max(q.Limit, 0), readPageSize))
	if q.Limit <= 0 {
		return out, nil
	}
	params := sqlcgen.ListAlarmsParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, FromName: q.FromName, Prefix: q.Prefix, State: q.State, ActionPrefix: q.ActionPrefix, ParentOf: q.ParentOf, SuppressedBy: q.SuppressedBy, PageLimit: int64(min(q.Limit, readPageSize))}
	for {
		rows, err := r.q.ListAlarms(r.ctx, params)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if len(q.Names) != 0 && !slices.Contains(q.Names, row.Name) || len(q.Types) != 0 && !slices.Contains(q.Types, row.AlarmType) {
				continue
			}
			alarm, err := r.alarm(row)
			if err != nil {
				return nil, err
			}
			out = append(out, alarm)
			if len(out) == q.Limit {
				return out, nil
			}
		}
		if len(rows) < int(params.PageLimit) {
			return out, r.ctx.Err()
		}
		params.HasAfter = 1
		params.AfterName = rows[len(rows)-1].Name
		params.PageLimit = int64(min(q.Limit-len(out), readPageSize))
	}
}

func (r reader) NextAlarmEvaluation() (scheduler.Job, bool, error) {
	row, err := r.q.NextAlarmEvaluation(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	alarm := domain.AlarmRecord{NextEvaluation: alarmTimePointer(row.NextEvaluation), SuppressionUntil: alarmTimePointer(row.SuppressionUntil)}
	due, scheduled := alarm.EvaluationDeadline()
	return scheduler.Job{Key: row.ID, Version: uint64(row.Version), Due: due}, scheduled, nil
}

func (r reader) AlarmHistory(q domain.AlarmHistoryQuery) ([]domain.AlarmHistoryRecord, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]domain.AlarmHistoryRecord, 0, min(max(q.Limit, 0), readPageSize))
	if q.Limit <= 0 {
		return out, nil
	}
	params := sqlcgen.ListAlarmHistoryAscendingParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, Name: q.Name, Type: q.Type, ContributorID: q.ContributorID, StartTime: q.Start.UTC(), EndTime: q.End.UTC(), PageLimit: int64(min(q.Limit, readPageSize))}
	if q.Contributors {
		params.Contributors = 1
	}
	if !q.Start.IsZero() {
		params.HasStart = 1
	}
	if !q.End.IsZero() {
		params.HasEnd = 1
	}
	if q.AfterAt != nil {
		params.HasAfter = 1
		params.AfterAt = q.AfterAt.UTC()
		params.AfterID = q.AfterID
	}
	for {
		var rows []sqlcgen.CloudwatchAlarmHistory
		var err error
		if q.Descending {
			rows, err = r.q.ListAlarmHistoryDescending(r.ctx, sqlcgen.ListAlarmHistoryDescendingParams(params))
		} else {
			rows, err = r.q.ListAlarmHistoryAscending(r.ctx, params)
		}
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if len(q.AlarmTypes) != 0 && !slices.Contains(q.AlarmTypes, row.AlarmType) {
				continue
			}
			history := domain.AlarmHistoryRecord{ID: row.ID, Key: domain.AlarmKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}, AlarmType: row.AlarmType, Type: row.Type, Summary: row.Summary, At: row.At.UTC(), Data: row.Data}
			if row.ContributorID.Valid {
				attributes, err := r.q.ListAlarmHistoryContributorAttributes(r.ctx, row.ID)
				if err != nil {
					return nil, err
				}
				history.Contributor = &domain.AlarmContributorIdentity{ID: row.ContributorID.String, Attributes: make(map[string]string, len(attributes))}
				for _, attribute := range attributes {
					history.Contributor.Attributes[attribute.Key] = attribute.Value
				}
			}
			out = append(out, history)
			if len(out) == q.Limit {
				return out, nil
			}
		}
		if len(rows) < int(params.PageLimit) {
			return out, r.ctx.Err()
		}
		last := rows[len(rows)-1]
		params.HasAfter = 1
		params.AfterAt = last.At.UTC()
		params.AfterID = last.ID
		params.PageLimit = int64(min(q.Limit-len(out), readPageSize))
	}
}

func (r reader) AlarmAction(id string) (domain.AlarmActionRecord, error) {
	row, err := r.q.GetAlarmAction(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AlarmActionRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AlarmActionRecord{}, err
	}
	action := domain.AlarmActionRecord{
		ID: row.ID, EventID: row.EventID, RequestID: row.RequestID,
		Key:       domain.AlarmKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		AlarmType: row.AlarmType, TargetARN: row.TargetArn, State: row.State, Payload: row.Payload, Subject: row.Subject, Accepted: row.Accepted.UTC(), Due: row.Due.UTC(), Version: uint64(row.Version), Attempts: row.Attempts,
	}
	if row.ContributorID.Valid {
		attributes, err := r.q.ListAlarmActionContributorAttributes(r.ctx, row.ID)
		if err != nil {
			return domain.AlarmActionRecord{}, err
		}
		action.Contributor = &domain.AlarmContributorIdentity{ID: row.ContributorID.String, Attributes: make(map[string]string, len(attributes))}
		for _, attribute := range attributes {
			action.Contributor.Attributes[attribute.Key] = attribute.Value
		}
	}
	return action, nil
}

func (r reader) NextAlarmAction() (scheduler.Job, bool, error) {
	row, err := r.q.NextAlarmAction(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return scheduler.Job{}, false, nil
	}
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return scheduler.Job{Key: row.ID, Version: uint64(row.Version), Due: row.Due}, true, nil
}
