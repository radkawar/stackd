package cloudwatch

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

// TODO: Comeback implement log alarms through their owning query/evaluation engine.
func alarmTypes(input api.AlarmTypes) ([]string, *awswire.Error) {
	if len(input) == 0 {
		return []string{"MetricAlarm"}, nil
	}
	types := make([]string, 0, len(input))
	for _, kind := range input {
		if kind == "LogAlarm" {
			return nil, unsupported("CloudWatch log alarms are not implemented.")
		}
		types = append(types, string(kind))
	}
	slices.Sort(types)
	return slices.Compact(types), nil
}

func (s *Service) authorizeAlarmRead(tx Transaction, action string, names []string, wildcard bool) *awswire.Error {
	scope := scopeFor(tx.Context())
	if wildcard || len(names) == 0 {
		return s.authorizeAlarm(tx, action, AlarmRecord{Key: AlarmKey{Scope: scope}}, nil, nil, true)
	}
	for _, name := range names {
		key := AlarmKey{Scope: scope, Name: name}
		alarm, err := tx.Alarm(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return wireError(err)
		}
		if errors.Is(err, ErrNotFound) {
			alarm.Key = key
		}
		if w := s.authorizeAlarm(tx, action, alarm, nil, nil, false); w != nil {
			return w
		}
	}
	return nil
}

func (s *Service) describeAlarms(tx Transaction, in *api.DescribeAlarmsInput) (*api.DescribeAlarmsOutput, *awswire.Error) {
	types, w := alarmTypes(in.AlarmTypes)
	if w != nil {
		return nil, w
	}
	query := AlarmQuery{Scope: scopeFor(tx.Context()), Types: types, Prefix: value(in.AlarmNamePrefix), State: value(in.StateValue), ActionPrefix: value(in.ActionPrefix), FromName: value(in.NextToken)}
	for _, name := range in.AlarmNames {
		query.Names = append(query.Names, string(name))
	}
	relationship := in.ChildrenOfAlarmName != nil || in.ParentsOfAlarmName != nil
	if relationship {
		if in.ChildrenOfAlarmName != nil && in.ParentsOfAlarmName != nil || in.ActionPrefix != nil || in.AlarmNamePrefix != nil || in.AlarmNames != nil || in.AlarmTypes != nil || in.StateValue != nil {
			return nil, alarmInvalid("ChildrenOfAlarmName and ParentsOfAlarmName may only be combined with MaxRecords and NextToken.")
		}
		query.Types = []string{"MetricAlarm", "CompositeAlarm"}
	}
	if w := s.authorizeAlarmRead(tx, "DescribeAlarms", query.Names, relationship || slices.Contains(types, "CompositeAlarm")); w != nil {
		return nil, w
	}
	out := &api.DescribeAlarmsOutput{MetricAlarms: api.MetricAlarms{}, CompositeAlarms: api.CompositeAlarms{}}
	if in.ChildrenOfAlarmName != nil {
		parent, err := tx.Alarm(AlarmKey{Scope: query.Scope, Name: value(in.ChildrenOfAlarmName)})
		if errors.Is(err, ErrNotFound) {
			return out, nil
		}
		if err != nil {
			return nil, wireError(err)
		}
		if parent.Composite == nil || len(parent.Composite.Children) == 0 {
			return out, nil
		}
		query.Names = parent.Composite.Children
	}
	if in.ParentsOfAlarmName != nil {
		query.ParentOf = value(in.ParentsOfAlarmName)
	}
	limit := 100
	if in.MaxRecords != nil {
		limit = int(*in.MaxRecords)
	}
	query.Limit = limit + 1
	records, err := tx.Alarms(query)
	if err != nil {
		return nil, wireError(err)
	}
	if len(records) > limit {
		out.NextToken = new(api.NextToken(records[limit].Key.Name))
		records = records[:limit]
	}
	for _, alarm := range records {
		observeCloudFormation(tx.Context(), alarm.Type(), alarm.Key.Name, alarm.CFNOwner)
		if alarm.Composite != nil {
			description := alarmCompositeDescription(alarm)
			if relationship {
				description = api.CompositeAlarm{AlarmName: description.AlarmName, AlarmArn: description.AlarmArn}
				if in.ChildrenOfAlarmName != nil {
					description.StateValue = new(api.StateValue(alarm.State.Value))
					description.StateUpdatedTimestamp = new(api.Timestamp(alarm.State.Updated))
				}
			}
			out.CompositeAlarms = append(out.CompositeAlarms, description)
		} else {
			description := alarmMetricDescription(alarm)
			if relationship {
				description = api.MetricAlarm{AlarmName: description.AlarmName, AlarmArn: description.AlarmArn, StateValue: description.StateValue, StateUpdatedTimestamp: description.StateUpdatedTimestamp}
			}
			out.MetricAlarms = append(out.MetricAlarms, description)
		}
	}
	return out, nil
}

func (s *Service) describeAlarmsForMetric(tx Transaction, in *api.DescribeAlarmsForMetricInput) (*api.DescribeAlarmsForMetricOutput, *awswire.Error) {
	if w := s.authorize(tx, "DescribeAlarmsForMetric", ""); w != nil {
		return nil, w
	}
	if in.Statistic != nil && in.ExtendedStatistic != nil {
		return nil, alarmInvalid("Specify either Statistic or ExtendedStatistic, not both.")
	}
	if in.ExtendedStatistic != nil {
		if _, valid := parseStatistic(value(in.ExtendedStatistic)); !valid {
			return nil, invalid("The specified ExtendedStatistic is not supported.")
		}
	}
	key, _, w := metricIdentity(scopeFor(tx.Context()), value(in.Namespace), value(in.MetricName), in.Dimensions)
	if w != nil {
		return nil, alarmInvalid(w.Message)
	}
	out := &api.DescribeAlarmsForMetricOutput{MetricAlarms: api.MetricAlarms{}}
	query := AlarmQuery{Scope: key.Scope, Types: []string{"MetricAlarm"}, Limit: 101}
	for {
		records, err := tx.Alarms(query)
		if err != nil {
			return nil, wireError(err)
		}
		more := len(records) > 100
		if more {
			query.FromName = records[100].Key.Name
			records = records[:100]
		}
		for _, alarm := range records {
			metric := alarm.Metric.Metric
			if metric == nil || metric.Key != key {
				continue
			}
			if in.Statistic != nil && metric.Statistic != value(in.Statistic) || in.ExtendedStatistic != nil && metric.Statistic != value(in.ExtendedStatistic) || in.Period != nil && metric.Period != int32(*in.Period) || in.Unit != nil && metric.Unit != value(in.Unit) {
				continue
			}
			out.MetricAlarms = append(out.MetricAlarms, alarmMetricDescription(alarm))
		}
		if !more {
			break
		}
	}
	return out, nil
}

type alarmHistoryCursor struct {
	Selection string
	At        time.Time
	ID        string
}

func (s *Service) describeAlarmHistory(tx Transaction, in *api.DescribeAlarmHistoryInput) (*api.DescribeAlarmHistoryOutput, *awswire.Error) {
	historyType := value(in.HistoryItemType)
	contributorType := historyType == "AlarmContributorAction" || historyType == "AlarmContributorStateUpdate"
	contributors := in.AlarmContributorId != nil || contributorType
	if contributors && in.AlarmName == nil {
		return nil, alarmInvalid("Alarm name must be provided to query history for alarm contributors.")
	}
	if in.AlarmContributorId != nil && in.HistoryItemType != nil && !contributorType {
		return nil, alarmInvalid(historyType + " is not supported history item type for alarm contributor.")
	}
	types, w := alarmTypes(in.AlarmTypes)
	if w != nil {
		return nil, w
	}
	if contributors && slices.Contains(types, "CompositeAlarm") {
		return nil, alarmInvalid("Alarm contributor history cannot be requested for composite alarm type.")
	}
	var names []string
	if in.AlarmName != nil {
		names = []string{value(in.AlarmName)}
	}
	if w := s.authorizeAlarmRead(tx, "DescribeAlarmHistory", names, slices.Contains(types, "CompositeAlarm")); w != nil {
		return nil, w
	}
	query := AlarmHistoryQuery{Scope: scopeFor(tx.Context()), Name: value(in.AlarmName), ContributorID: value(in.AlarmContributorId), Contributors: contributors, AlarmTypes: types, Type: historyType, Descending: value(in.ScanBy) != "TimestampAscending"}
	if in.StartDate != nil {
		query.Start = time.Time(*in.StartDate)
	}
	if in.EndDate != nil {
		query.End = time.Time(*in.EndDate)
	}
	if !query.Start.IsZero() && !query.End.IsZero() && query.Start.After(query.End) {
		return nil, alarmInvalid("StartDate must not be after EndDate.")
	}
	selection, _ := json.Marshal(query)
	if in.NextToken != nil {
		encoded, err := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		var cursor alarmHistoryCursor
		if err != nil || json.Unmarshal(encoded, &cursor) != nil || cursor.Selection != string(selection) || cursor.ID == "" || cursor.At.IsZero() {
			return nil, failure("InvalidNextToken", "Invalid NextToken : "+value(in.NextToken))
		}
		query.AfterAt, query.AfterID = &cursor.At, cursor.ID
	}
	limit := 100
	if in.MaxRecords != nil {
		limit = int(*in.MaxRecords)
	}
	query.Limit = limit + 1
	if w := s.expireAlarmHistory(tx, query.Scope); w != nil {
		return nil, w
	}
	records, err := tx.AlarmHistory(query)
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.DescribeAlarmHistoryOutput{AlarmHistoryItems: api.AlarmHistoryItems{}}
	if len(records) > limit {
		last := records[limit-1]
		encoded, _ := json.Marshal(alarmHistoryCursor{Selection: string(selection), At: last.At, ID: last.ID})
		out.NextToken = new(api.NextToken(base64.RawURLEncoding.EncodeToString(encoded)))
		records = records[:limit]
	}
	for _, history := range records {
		item := api.AlarmHistoryItem{AlarmName: new(api.AlarmName(history.Key.Name)), AlarmType: new(api.AlarmType(history.AlarmType)), Timestamp: new(api.Timestamp(history.At)), HistoryItemType: new(api.HistoryItemType(history.Type)), HistorySummary: new(api.HistorySummary(history.Summary)), HistoryData: new(api.HistoryData(history.Data))}
		if history.Contributor != nil {
			item.AlarmContributorId = new(api.ContributorId(history.Contributor.ID))
			item.AlarmContributorAttributes = contributorAttributes(history.Contributor.Attributes)
		}
		out.AlarmHistoryItems = append(out.AlarmHistoryItems, item)
	}
	return out, nil
}
