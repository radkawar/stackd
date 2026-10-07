package applicationautoscaling

import (
	api "stackd/internal/awsapi/applicationautoscaling"
	domain "stackd/storage/applicationautoscaling"
	"stackd/storage/sqlite/applicationautoscaling/internal/sqlcgen"
)

func (r reader) Policy(key domain.PolicyKey) (domain.PolicyRecord, error) {
	row, err := r.q.GetPolicy(r.ctx, sqlcgen.GetPolicyParams{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension, Name: key.Name})
	if err != nil {
		return domain.PolicyRecord{}, missing(err)
	}
	return r.policy(row)
}
func (r reader) Policies(q domain.PolicyQuery) ([]domain.PolicyRecord, error) {
	from := listCursor(q.From)
	rows, err := r.q.ListPolicies(r.ctx, sqlcgen.ListPoliciesParams{Partition: q.Partition, AccountID: q.AccountID, Region: q.Region, Namespace: q.Namespace, FilterResourceID: q.ResourceID, FilterDimension: q.Dimension, HasNames: flag(len(q.Names) != 0), Names: namesJSON(q.Names), RowLimit: rowLimit(q.Limit), FromResourceID: from.ResourceID, FromDimension: from.Dimension, FromName: from.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PolicyRecord, 0, len(rows))
	for _, row := range rows {
		record, err := r.policy(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}
func (r reader) policy(row sqlcgen.AasPolicy) (domain.PolicyRecord, error) {
	out := domain.PolicyRecord{Ownership: row.Ownership, Key: domain.PolicyKey{TargetKey: targetKey(row.Partition, row.AccountID, row.Region, row.Namespace, row.ResourceID, row.Dimension), Name: row.Name}, ManagedActionID: row.ManagedActionID, LastScaleAt: row.LastScaleAt, LastScaleFrom: int32(row.LastScaleFrom), LastScaleTo: int32(row.LastScaleTo),
		PendingActivityID: row.PendingActivityID,
		Data:              api.ScalingPolicy{CreationTime: timePointer(row.CreationTime), PolicyARN: stringPointer[api.ResourceIdMaxLen1600](row.PolicyArn), PolicyName: stringPointer[api.PolicyName](row.PolicyName), PolicyType: stringPointer[api.PolicyType](row.PolicyType), ResourceId: stringPointer[api.ResourceIdMaxLen1600](row.DataResourceID), ScalableDimension: stringPointer[api.ScalableDimension](row.DataDimension), ServiceNamespace: stringPointer[api.ServiceNamespace](row.DataNamespace)}}
	if row.HasAlarms {
		rows, err := r.q.ListPolicyAlarms(r.ctx, row.PolicyPk)
		if err != nil {
			return domain.PolicyRecord{}, err
		}
		out.Data.Alarms = make(api.Alarms, len(rows))
		for i, alarm := range rows {
			out.Data.Alarms[i] = api.Alarm{AlarmARN: stringPointer[api.ResourceId](alarm.AlarmArn), AlarmName: stringPointer[api.ResourceId](alarm.AlarmName)}
		}
	}
	if row.HasStep {
		step := &api.StepScalingPolicyConfiguration{AdjustmentType: stringPointer[api.AdjustmentType](row.StepAdjustmentType), Cooldown: intPointer[api.Cooldown](row.StepCooldown), MetricAggregationType: stringPointer[api.MetricAggregationType](row.StepAggregationType), MinAdjustmentMagnitude: intPointer[api.MinAdjustmentMagnitude](row.StepMinAdjustment)}
		if row.HasSteps {
			rows, err := r.q.ListPolicySteps(r.ctx, row.PolicyPk)
			if err != nil {
				return domain.PolicyRecord{}, err
			}
			step.StepAdjustments = make(api.StepAdjustments, len(rows))
			for i, interval := range rows {
				step.StepAdjustments[i] = api.StepAdjustment{MetricIntervalLowerBound: floatPointer[api.MetricScale](interval.LowerBound), MetricIntervalUpperBound: floatPointer[api.MetricScale](interval.UpperBound), ScalingAdjustment: intPointer[api.ScalingAdjustment](interval.Adjustment)}
			}
		}
		out.Data.StepScalingPolicyConfiguration = step
	}
	if row.HasTracking {
		tracking := &api.TargetTrackingScalingPolicyConfiguration{DisableScaleIn: boolPointer[api.DisableScaleIn](row.DisableScaleIn), ScaleInCooldown: intPointer[api.Cooldown](row.ScaleInCooldown), ScaleOutCooldown: intPointer[api.Cooldown](row.ScaleOutCooldown), TargetValue: floatPointer[api.MetricScale](row.TargetValue)}
		if row.HasPredefined {
			tracking.PredefinedMetricSpecification = &api.PredefinedMetricSpecification{PredefinedMetricType: stringPointer[api.MetricType](row.PredefinedMetricType), ResourceLabel: stringPointer[api.ResourceLabel](row.ResourceLabel)}
		}
		if row.HasCustom {
			custom, err := r.customMetric(row)
			if err != nil {
				return domain.PolicyRecord{}, err
			}
			tracking.CustomizedMetricSpecification = custom
		}
		out.Data.TargetTrackingScalingPolicyConfiguration = tracking
	}
	return out, nil
}

func (r reader) customMetric(row sqlcgen.AasPolicy) (*api.CustomizedMetricSpecification, error) {
	out := &api.CustomizedMetricSpecification{MetricName: stringPointer[api.MetricName](row.CustomMetricName), Namespace: stringPointer[api.MetricNamespace](row.CustomNamespace), Statistic: stringPointer[api.MetricStatistic](row.CustomStatistic), Unit: stringPointer[api.MetricUnit](row.CustomUnit)}
	dimensions, err := r.q.ListPolicyDimensions(r.ctx, row.PolicyPk)
	if err != nil {
		return nil, err
	}
	if row.HasCustomDimensions {
		out.Dimensions = make(api.MetricDimensions, 0)
	}
	dimensionIndex := 0
	for dimensionIndex < len(dimensions) && dimensions[dimensionIndex].MetricPosition == -1 {
		d := dimensions[dimensionIndex]
		out.Dimensions = append(out.Dimensions, api.MetricDimension{Name: stringPointer[api.MetricDimensionName](d.Name), Value: stringPointer[api.MetricDimensionValue](d.Value)})
		dimensionIndex++
	}
	if row.HasMetricQueries {
		queries, err := r.q.ListPolicyMetricQueries(r.ctx, row.PolicyPk)
		if err != nil {
			return nil, err
		}
		out.Metrics = make(api.TargetTrackingMetricDataQueries, len(queries))
		for i, query := range queries {
			metricQuery := api.TargetTrackingMetricDataQuery{Expression: stringPointer[api.Expression](query.Expression), Id: stringPointer[api.Id](query.QueryID), Label: stringPointer[api.XmlString](query.Label), ReturnData: boolPointer[api.ReturnData](query.ReturnData)}
			if query.HasStat {
				stat := &api.TargetTrackingMetricStat{Stat: stringPointer[api.XmlString](query.Stat), Unit: stringPointer[api.TargetTrackingMetricUnit](query.Unit)}
				if query.HasMetric {
					metric := &api.TargetTrackingMetric{MetricName: stringPointer[api.TargetTrackingMetricName](query.MetricName), Namespace: stringPointer[api.TargetTrackingMetricNamespace](query.Namespace)}
					if query.HasDimensions {
						metric.Dimensions = make(api.TargetTrackingMetricDimensions, 0)
					}
					for dimensionIndex < len(dimensions) && dimensions[dimensionIndex].MetricPosition == query.Position {
						d := dimensions[dimensionIndex]
						metric.Dimensions = append(metric.Dimensions, api.TargetTrackingMetricDimension{Name: stringPointer[api.TargetTrackingMetricDimensionName](d.Name), Value: stringPointer[api.TargetTrackingMetricDimensionValue](d.Value)})
						dimensionIndex++
					}
					stat.Metric = metric
				}
				metricQuery.MetricStat = stat
			}
			out.Metrics[i] = metricQuery
		}
	}
	return out, nil
}
