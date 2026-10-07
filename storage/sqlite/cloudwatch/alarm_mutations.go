package cloudwatch

import (
	"time"

	domain "stackd/storage/cloudwatch"
	"stackd/storage/sqlite/cloudwatch/internal/sqlcgen"
)

func (w writer) PutAlarm(alarm domain.AlarmRecord) error {
	k := alarm.Key
	if err := w.q.PutAlarm(w.ctx, sqlcgen.PutAlarmParams{
		ID: alarm.ID, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		CfnOwner:  alarm.CFNOwner,
		AlarmType: alarm.Type(), Version: int64(alarm.Version), Created: alarm.Created.UTC(), Updated: alarm.Updated.UTC(), Description: alarmString(alarm.Description), ActionsEnabled: alarm.ActionsEnabled,
		StateValue: alarm.State.Value, StateReason: alarmString(alarm.State.Reason), StateReasonData: alarm.State.ReasonData, StateUpdated: alarm.State.Updated.UTC(), StateTransitioned: alarm.State.Transitioned.UTC(),
		NextEvaluation: alarmTime(alarm.NextEvaluation), SuppressionPhase: alarm.SuppressionPhase, SuppressionReason: alarm.SuppressionReason, SuppressionUntil: alarmTime(alarm.SuppressionUntil),
		StateEventID: alarm.State.Origin.EventID, StateRequestID: alarm.State.Origin.RequestID, EvaluationEventID: alarm.EvaluationOrigin.EventID, EvaluationRequestID: alarm.EvaluationOrigin.RequestID,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmMetricConfig(w.ctx, alarm.ID); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmQueries(w.ctx, alarm.ID); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmMetricStats(w.ctx, alarm.ID); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmCompositeConfig(w.ctx, alarm.ID); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmChildren(w.ctx, alarm.ID); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmTargets(w.ctx, alarm.ID); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmTags(w.ctx, alarm.ID); err != nil {
		return err
	}
	if config := alarm.Metric; config != nil {
		if err := w.q.PutAlarmMetricConfig(w.ctx, sqlcgen.PutAlarmMetricConfigParams{AlarmID: alarm.ID, QueryID: config.QueryID, Comparison: config.Comparison, Threshold: config.Threshold, EvaluationPeriods: int64(config.EvaluationPeriods), DatapointsToAlarm: alarmInt(config.DatapointsToAlarm), TreatMissingData: config.TreatMissingData, LowSampleCount: config.LowSampleCount}); err != nil {
			return err
		}
		if config.Metric != nil {
			if err := w.putAlarmMetric(alarm.ID, -1, *config.Metric); err != nil {
				return err
			}
		}
		for i, query := range config.Queries {
			if err := w.q.PutAlarmQuery(w.ctx, sqlcgen.PutAlarmQueryParams{AlarmID: alarm.ID, Position: int64(i), QueryID: query.ID, Expression: query.Expression, AccountID: query.AccountID, Label: alarmString(query.Label), Period: alarmInt(query.Period), ReturnData: alarmBool(query.ReturnData)}); err != nil {
				return err
			}
			if query.Metric != nil {
				if err := w.putAlarmMetric(alarm.ID, int64(i), *query.Metric); err != nil {
					return err
				}
			}
		}
	}
	if config := alarm.Composite; config != nil {
		if err := w.q.PutAlarmCompositeConfig(w.ctx, sqlcgen.PutAlarmCompositeConfigParams{AlarmID: alarm.ID, Rule: config.Rule, Suppressor: config.Suppressor, WaitPeriod: int64(config.WaitPeriod), ExtensionPeriod: int64(config.ExtensionPeriod)}); err != nil {
			return err
		}
		for i, child := range config.Children {
			if err := w.q.PutAlarmChild(w.ctx, sqlcgen.PutAlarmChildParams{AlarmID: alarm.ID, Position: int64(i), Name: child}); err != nil {
				return err
			}
		}
	}
	for _, group := range []struct {
		state   string
		targets []string
	}{
		{"ALARM", alarm.Actions.Alarm}, {"OK", alarm.Actions.OK}, {"INSUFFICIENT_DATA", alarm.Actions.InsufficientData},
	} {
		for i, target := range group.targets {
			if err := w.q.PutAlarmTarget(w.ctx, sqlcgen.PutAlarmTargetParams{AlarmID: alarm.ID, State: group.state, Position: int64(i), Arn: target}); err != nil {
				return err
			}
		}
	}
	for key, value := range alarm.Tags {
		if err := w.q.PutAlarmTag(w.ctx, sqlcgen.PutAlarmTagParams{AlarmID: alarm.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) UpdateAlarmEvaluation(alarm domain.AlarmRecord) error {
	affected, err := w.q.UpdateAlarmEvaluation(w.ctx, sqlcgen.UpdateAlarmEvaluationParams{
		ID: alarm.ID, Version: int64(alarm.Version),
		StateValue: alarm.State.Value, StateReason: alarmString(alarm.State.Reason), StateReasonData: alarm.State.ReasonData, StateUpdated: alarm.State.Updated.UTC(), StateTransitioned: alarm.State.Transitioned.UTC(),
		NextEvaluation: alarmTime(alarm.NextEvaluation), SuppressionPhase: alarm.SuppressionPhase, SuppressionReason: alarm.SuppressionReason, SuppressionUntil: alarmTime(alarm.SuppressionUntil),
		StateEventID: alarm.State.Origin.EventID, StateRequestID: alarm.State.Origin.RequestID, EvaluationEventID: alarm.EvaluationOrigin.EventID, EvaluationRequestID: alarm.EvaluationOrigin.RequestID,
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (w writer) putAlarmMetric(alarmID string, position int64, metric domain.AlarmMetricStat) error {
	k := metric.Key
	if err := w.q.PutAlarmMetricStat(w.ctx, sqlcgen.PutAlarmMetricStatParams{AlarmID: alarmID, Position: position, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Namespace: k.Namespace, Name: k.Name, Dimensions: k.Dimensions, Period: int64(metric.Period), Statistic: metric.Statistic, Unit: metric.Unit}); err != nil {
		return err
	}
	for i, dimension := range metric.Dimensions {
		if err := w.q.PutAlarmDimension(w.ctx, sqlcgen.PutAlarmDimensionParams{AlarmID: alarmID, MetricPosition: position, Position: int64(i), Name: dimension.Name, Value: dimension.Value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteAlarm(key domain.AlarmKey) error {
	return w.q.DeleteAlarm(w.ctx, sqlcgen.DeleteAlarmParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name})
}

func (w writer) AppendAlarmHistory(history domain.AlarmHistoryRecord) error {
	k := history.Key
	if err := w.q.AppendAlarmHistory(w.ctx, sqlcgen.AppendAlarmHistoryParams{ID: history.ID, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, AlarmType: history.AlarmType, Type: history.Type, Summary: history.Summary, At: history.At.UTC(), Data: history.Data, ContributorID: alarmContributorID(history.Contributor)}); err != nil {
		return err
	}
	if history.Contributor != nil {
		for key, value := range history.Contributor.Attributes {
			if err := w.q.PutAlarmHistoryContributorAttribute(w.ctx, sqlcgen.PutAlarmHistoryContributorAttributeParams{HistoryID: history.ID, Key: key, Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) PutAlarmAction(action domain.AlarmActionRecord) error {
	k := action.Key
	payload := action.Payload
	if payload == nil {
		payload = []byte{}
	}
	if err := w.q.PutAlarmAction(w.ctx, sqlcgen.PutAlarmActionParams{
		ID: action.ID, EventID: action.EventID, RequestID: action.RequestID, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		AlarmType: action.AlarmType, TargetArn: action.TargetARN, State: action.State, Payload: payload, Subject: action.Subject, Accepted: action.Accepted.UTC(), Due: action.Due.UTC(), Version: int64(action.Version), Attempts: action.Attempts, ContributorID: alarmContributorID(action.Contributor),
	}); err != nil {
		return err
	}
	if err := w.q.DeleteAlarmActionContributorAttributes(w.ctx, action.ID); err != nil {
		return err
	}
	if action.Contributor != nil {
		for key, value := range action.Contributor.Attributes {
			if err := w.q.PutAlarmActionContributorAttribute(w.ctx, sqlcgen.PutAlarmActionContributorAttributeParams{ActionID: action.ID, Key: key, Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w writer) DeleteAlarmAction(id string) error {
	return w.q.DeleteAlarmAction(w.ctx, id)
}

func (w writer) ExpireAlarmHistory(scope domain.Scope, cutoff time.Time) error {
	return w.q.ExpireAlarmHistory(w.ctx, sqlcgen.ExpireAlarmHistoryParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Cutoff: cutoff.UTC()})
}
