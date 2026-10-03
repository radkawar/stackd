package cloudwatch

import api "stackd/internal/awsapi/cloudwatch"

func alarmResourceList(values []string) api.ResourceList {
	out := make(api.ResourceList, len(values))
	for i, value := range values {
		out[i] = api.ResourceName(value)
	}
	return out
}

func alarmDimensions(values []Dimension) api.Dimensions {
	out := make(api.Dimensions, len(values))
	for i, value := range values {
		out[i] = api.Dimension{Name: new(api.DimensionName(value.Name)), Value: new(api.DimensionValue(value.Value))}
	}
	return out
}

func alarmQueryInput(query AlarmMetricQuery) api.MetricDataQuery {
	out := api.MetricDataQuery{Id: new(api.MetricId(query.ID))}
	if query.AccountID != "" {
		out.AccountId = new(api.AccountId(query.AccountID))
	}
	if query.Expression != "" {
		out.Expression = new(api.MetricExpression(query.Expression))
	}
	if query.Label != nil {
		out.Label = new(api.MetricLabel(*query.Label))
	}
	if query.Period != nil {
		out.Period = new(api.Period(*query.Period))
	}
	if query.ReturnData != nil {
		out.ReturnData = new(api.ReturnData(*query.ReturnData))
	}
	if query.Metric != nil {
		metric := query.Metric
		out.MetricStat = &api.MetricStat{Metric: &api.Metric{Namespace: new(api.Namespace(metric.Key.Namespace)), MetricName: new(api.MetricName(metric.Key.Name)), Dimensions: alarmDimensions(metric.Dimensions)}, Period: new(api.Period(metric.Period)), Stat: new(api.Stat(metric.Statistic))}
		if metric.Unit != "" {
			out.MetricStat.Unit = new(api.StandardUnit(metric.Unit))
		}
	}
	return out
}

func alarmMetricDescription(alarm AlarmRecord) api.MetricAlarm {
	config := alarm.Metric
	out := api.MetricAlarm{
		AlarmName: new(api.AlarmName(alarm.Key.Name)), AlarmArn: new(api.AlarmArn(alarm.Key.ARN())),
		AlarmConfigurationUpdatedTimestamp: new(api.Timestamp(alarm.Updated)), ActionsEnabled: new(api.ActionsEnabled(alarm.ActionsEnabled)),
		AlarmActions: alarmResourceList(alarm.Actions.Alarm), OKActions: alarmResourceList(alarm.Actions.OK), InsufficientDataActions: alarmResourceList(alarm.Actions.InsufficientData),
		StateValue: new(api.StateValue(alarm.State.Value)), StateUpdatedTimestamp: new(api.Timestamp(alarm.State.Updated)), StateTransitionedTimestamp: new(api.Timestamp(alarm.State.Transitioned)),
		ComparisonOperator: new(api.ComparisonOperator(config.Comparison)), EvaluationPeriods: new(api.EvaluationPeriods(config.EvaluationPeriods)), Threshold: new(api.Threshold(config.Threshold)),
	}
	if alarm.Description != nil {
		out.AlarmDescription = new(api.AlarmDescription(*alarm.Description))
	}
	if alarm.State.Reason != nil {
		out.StateReason = new(api.StateReason(*alarm.State.Reason))
	}
	if alarm.State.ReasonData != "" {
		out.StateReasonData = new(api.StateReasonData(alarm.State.ReasonData))
	}
	if config.DatapointsToAlarm != nil {
		out.DatapointsToAlarm = new(api.DatapointsToAlarm(*config.DatapointsToAlarm))
	}
	if config.TreatMissingData != "" {
		out.TreatMissingData = new(api.TreatMissingData(config.TreatMissingData))
	}
	if config.LowSampleCount != "" {
		out.EvaluateLowSampleCountPercentile = new(api.EvaluateLowSampleCountPercentile(config.LowSampleCount))
	}
	if config.Metric != nil {
		metric := config.Metric
		out.Namespace, out.MetricName = new(api.Namespace(metric.Key.Namespace)), new(api.MetricName(metric.Key.Name))
		out.Dimensions, out.Period = alarmDimensions(metric.Dimensions), new(api.Period(metric.Period))
		if basicStatistic(metric.Statistic) {
			out.Statistic = new(api.Statistic(metric.Statistic))
		} else {
			out.ExtendedStatistic = new(api.ExtendedStatistic(metric.Statistic))
		}
		if metric.Unit != "" {
			out.Unit = new(api.StandardUnit(metric.Unit))
		}
	} else {
		out.Metrics = make(api.MetricDataQueries, len(config.Queries))
		for i, query := range config.Queries {
			out.Metrics[i] = alarmQueryInput(query)
		}
	}
	return out
}

func alarmCompositeDescription(alarm AlarmRecord) api.CompositeAlarm {
	config := alarm.Composite
	out := api.CompositeAlarm{
		AlarmName: new(api.AlarmName(alarm.Key.Name)), AlarmArn: new(api.AlarmArn(alarm.Key.ARN())), AlarmRule: new(api.AlarmRule(config.Rule)),
		AlarmConfigurationUpdatedTimestamp: new(api.Timestamp(alarm.Updated)), ActionsEnabled: new(api.ActionsEnabled(alarm.ActionsEnabled)),
		AlarmActions: alarmResourceList(alarm.Actions.Alarm), OKActions: alarmResourceList(alarm.Actions.OK), InsufficientDataActions: alarmResourceList(alarm.Actions.InsufficientData),
		StateValue: new(api.StateValue(alarm.State.Value)), StateUpdatedTimestamp: new(api.Timestamp(alarm.State.Updated)), StateTransitionedTimestamp: new(api.Timestamp(alarm.State.Transitioned)),
	}
	if alarm.Description != nil {
		out.AlarmDescription = new(api.AlarmDescription(*alarm.Description))
	}
	if alarm.State.Reason != nil {
		out.StateReason = new(api.StateReason(*alarm.State.Reason))
	}
	if alarm.State.ReasonData != "" {
		out.StateReasonData = new(api.StateReasonData(alarm.State.ReasonData))
	}
	if config.Suppressor != "" {
		out.ActionsSuppressor = new(api.AlarmArn(config.Suppressor))
		out.ActionsSuppressorWaitPeriod = new(api.SuppressorPeriod(config.WaitPeriod))
		out.ActionsSuppressorExtensionPeriod = new(api.SuppressorPeriod(config.ExtensionPeriod))
	}
	if alarm.SuppressionPhase != "" {
		out.ActionsSuppressedBy = new(api.ActionsSuppressedBy(alarm.SuppressionPhase))
		out.ActionsSuppressedReason = new(api.ActionsSuppressedReason(alarmSuppressionReason(alarm)))
	}
	return out
}
