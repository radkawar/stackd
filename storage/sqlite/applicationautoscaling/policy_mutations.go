package applicationautoscaling

import (
	"errors"

	api "stackd/internal/awsapi/applicationautoscaling"
	domain "stackd/storage/applicationautoscaling"
	"stackd/storage/sqlite/applicationautoscaling/internal/sqlcgen"
)

func (w writer) PutPolicy(record domain.PolicyRecord) error {
	key, data := record.Key, record.Data
	if data.PredictiveScalingPolicyConfiguration != nil {
		return errors.New("predictive scaling policy persistence is unsupported")
	}
	p := sqlcgen.PutPolicyParams{Ownership: record.Ownership, Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension, Name: key.Name, ManagedActionID: record.ManagedActionID, LastScaleAt: record.LastScaleAt.UTC(), LastScaleFrom: int64(record.LastScaleFrom), LastScaleTo: int64(record.LastScaleTo), CreationTime: nullableTime(data.CreationTime), PolicyArn: nullableString(data.PolicyARN), PolicyName: nullableString(data.PolicyName), PolicyType: nullableString(data.PolicyType), DataResourceID: nullableString(data.ResourceId), DataDimension: nullableString(data.ScalableDimension), DataNamespace: nullableString(data.ServiceNamespace), HasAlarms: data.Alarms != nil, HasStep: data.StepScalingPolicyConfiguration != nil, HasTracking: data.TargetTrackingScalingPolicyConfiguration != nil}
	p.PendingActivityID = record.PendingActivityID
	if step := data.StepScalingPolicyConfiguration; step != nil {
		p.StepAdjustmentType = nullableString(step.AdjustmentType)
		p.StepCooldown = nullableInt(step.Cooldown)
		p.StepAggregationType = nullableString(step.MetricAggregationType)
		p.StepMinAdjustment = nullableInt(step.MinAdjustmentMagnitude)
		p.HasSteps = step.StepAdjustments != nil
	}
	if tracking := data.TargetTrackingScalingPolicyConfiguration; tracking != nil {
		p.DisableScaleIn = nullableBool(tracking.DisableScaleIn)
		p.ScaleInCooldown = nullableInt(tracking.ScaleInCooldown)
		p.ScaleOutCooldown = nullableInt(tracking.ScaleOutCooldown)
		p.TargetValue = nullableFloat(tracking.TargetValue)
		p.HasPredefined = tracking.PredefinedMetricSpecification != nil
		if predefined := tracking.PredefinedMetricSpecification; predefined != nil {
			p.PredefinedMetricType = nullableString(predefined.PredefinedMetricType)
			p.ResourceLabel = nullableString(predefined.ResourceLabel)
		}
		p.HasCustom = tracking.CustomizedMetricSpecification != nil
		if custom := tracking.CustomizedMetricSpecification; custom != nil {
			p.CustomMetricName = nullableString(custom.MetricName)
			p.CustomNamespace = nullableString(custom.Namespace)
			p.CustomStatistic = nullableString(custom.Statistic)
			p.CustomUnit = nullableString(custom.Unit)
			p.HasCustomDimensions = custom.Dimensions != nil
			p.HasMetricQueries = custom.Metrics != nil
		}
	}
	row, err := w.q.PutPolicy(w.ctx, p)
	if err != nil {
		return err
	}
	// Replacement clears only owned typed children; the policy identity and
	// cooldown row survive, and a failed write rolls back in the joined owner.
	if err := w.q.DeletePolicyAlarms(w.ctx, row.PolicyPk); err != nil {
		return err
	}
	if err := w.q.DeletePolicySteps(w.ctx, row.PolicyPk); err != nil {
		return err
	}
	if err := w.q.DeletePolicyDimensions(w.ctx, row.PolicyPk); err != nil {
		return err
	}
	if err := w.q.DeletePolicyMetricQueries(w.ctx, row.PolicyPk); err != nil {
		return err
	}
	for i, alarm := range data.Alarms {
		if err := w.q.InsertPolicyAlarm(w.ctx, sqlcgen.InsertPolicyAlarmParams{PolicyPk: row.PolicyPk, Position: int64(i), AlarmArn: nullableString(alarm.AlarmARN), AlarmName: nullableString(alarm.AlarmName)}); err != nil {
			return err
		}
	}
	if step := data.StepScalingPolicyConfiguration; step != nil {
		for i, interval := range step.StepAdjustments {
			if err := w.q.InsertPolicyStep(w.ctx, sqlcgen.InsertPolicyStepParams{PolicyPk: row.PolicyPk, Position: int64(i), LowerBound: nullableFloat(interval.MetricIntervalLowerBound), UpperBound: nullableFloat(interval.MetricIntervalUpperBound), Adjustment: nullableInt(interval.ScalingAdjustment)}); err != nil {
				return err
			}
		}
	}
	if tracking := data.TargetTrackingScalingPolicyConfiguration; tracking != nil && tracking.CustomizedMetricSpecification != nil {
		return w.putCustomMetric(row.PolicyPk, tracking.CustomizedMetricSpecification)
	}
	return nil
}

func (w writer) putCustomMetric(policyPk int64, custom *api.CustomizedMetricSpecification) error {
	for i, dimension := range custom.Dimensions {
		if err := w.q.InsertPolicyDimension(w.ctx, sqlcgen.InsertPolicyDimensionParams{PolicyPk: policyPk, MetricPosition: -1, Position: int64(i), Name: nullableString(dimension.Name), Value: nullableString(dimension.Value)}); err != nil {
			return err
		}
	}
	for i, query := range custom.Metrics {
		p := sqlcgen.InsertPolicyMetricQueryParams{PolicyPk: policyPk, Position: int64(i), Expression: nullableString(query.Expression), QueryID: nullableString(query.Id), Label: nullableString(query.Label), ReturnData: nullableBool(query.ReturnData), HasStat: query.MetricStat != nil}
		if stat := query.MetricStat; stat != nil {
			p.Stat = nullableString(stat.Stat)
			p.Unit = nullableString(stat.Unit)
			p.HasMetric = stat.Metric != nil
			if metric := stat.Metric; metric != nil {
				p.MetricName = nullableString(metric.MetricName)
				p.Namespace = nullableString(metric.Namespace)
				p.HasDimensions = metric.Dimensions != nil
			}
		}
		if err := w.q.InsertPolicyMetricQuery(w.ctx, p); err != nil {
			return err
		}
		if query.MetricStat != nil && query.MetricStat.Metric != nil {
			for j, dimension := range query.MetricStat.Metric.Dimensions {
				if err := w.q.InsertPolicyDimension(w.ctx, sqlcgen.InsertPolicyDimensionParams{PolicyPk: policyPk, MetricPosition: int64(i), Position: int64(j), Name: nullableString(dimension.Name), Value: nullableString(dimension.Value)}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (w writer) DeletePolicy(key domain.PolicyKey) error {
	return w.q.DeletePolicy(w.ctx, sqlcgen.DeletePolicyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension, Name: key.Name})
}
