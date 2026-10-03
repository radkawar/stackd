package autoscaling

import (
	"fmt"
	api "stackd/internal/awsapi/autoscaling"
	domain "stackd/storage/autoscaling"
	"stackd/storage/sqlite/autoscaling/internal/sqlcgen"
)

func (r reader) policy(row sqlcgen.AsgPolicy) (domain.PolicyRecord, error) {
	out := domain.PolicyRecord{
		Key:         domain.PolicyKey{GroupKey: groupKey(row.Partition, row.AccountID, row.Region, row.GroupName), Name: row.Name},
		GroupID:     row.GroupID,
		LastScaleAt: row.LastScaleAt.Time,
	}
	out.Data.AdjustmentType = stringPointer[api.XmlStringMaxLen255](row.DataAdjustmentType)
	if row.HasDataAlarms {
		var err error
		out.Data.Alarms, err = r.readPoliciesAlarms(row.PolicyPk)
		if err != nil {
			return domain.PolicyRecord{}, err
		}
	}
	out.Data.AutoScalingGroupName = stringPointer[api.XmlStringMaxLen255](row.DataAutoScalingGroupName)
	out.Data.Cooldown = intPointer[api.Cooldown](row.DataCooldown)
	out.Data.Enabled = boolPointer[api.ScalingPolicyEnabled](row.DataEnabled)
	out.Data.EstimatedInstanceWarmup = intPointer[api.EstimatedInstanceWarmup](row.DataEstimatedInstanceWarmup)
	out.Data.MetricAggregationType = stringPointer[api.XmlStringMaxLen32](row.DataMetricAggregationType)
	out.Data.MinAdjustmentMagnitude = intPointer[api.MinAdjustmentMagnitude](row.DataMinAdjustmentMagnitude)
	out.Data.MinAdjustmentStep = intPointer[api.MinAdjustmentStep](row.DataMinAdjustmentStep)
	out.Data.PolicyARN = stringPointer[api.ResourceName](row.DataPolicyArn)
	out.Data.PolicyName = stringPointer[api.XmlStringMaxLen255](row.DataPolicyName)
	out.Data.PolicyType = stringPointer[api.XmlStringMaxLen64](row.DataPolicyType)
	out.Data.ScalingAdjustment = intPointer[api.PolicyIncrement](row.DataScalingAdjustment)
	if row.HasDataStepAdjustments {
		var err error
		out.Data.StepAdjustments, err = r.readPoliciesStepAdjustments(row.PolicyPk)
		if err != nil {
			return domain.PolicyRecord{}, err
		}
	}
	if row.HasDataTargetTrackingConfiguration {
		out.Data.TargetTrackingConfiguration = &api.TargetTrackingConfiguration{}
	}
	if out.Data.TargetTrackingConfiguration != nil {
		if row.HasDataTargetTrackingConfigurationCustomizedMetricSpecification {
			out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification = &api.CustomizedMetricSpecification{}
		}
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		if row.HasDataTargetTrackingConfigurationCustomizedMetricSpecificationDimensions {
			var err error
			out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Dimensions, err = r.readPoliciesDimensions(row.PolicyPk)
			if err != nil {
				return domain.PolicyRecord{}, err
			}
		}
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.MetricName = stringPointer[api.MetricName](row.DataTargetTrackingConfigurationCustomizedMetricSpecificationMetricName)
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		if row.HasDataTargetTrackingConfigurationCustomizedMetricSpecificationMetrics {
			var err error
			out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Metrics, err = r.readPoliciesMetrics(row.PolicyPk)
			if err != nil {
				return domain.PolicyRecord{}, err
			}
		}
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Namespace = stringPointer[api.MetricNamespace](row.DataTargetTrackingConfigurationCustomizedMetricSpecificationNamespace)
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Period = intPointer[api.MetricGranularityInSeconds](row.DataTargetTrackingConfigurationCustomizedMetricSpecificationPeriod)
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Statistic = stringPointer[api.MetricStatistic](row.DataTargetTrackingConfigurationCustomizedMetricSpecificationStatistic)
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		out.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Unit = stringPointer[api.MetricUnit](row.DataTargetTrackingConfigurationCustomizedMetricSpecificationUnit)
	}
	if out.Data.TargetTrackingConfiguration != nil {
		out.Data.TargetTrackingConfiguration.DisableScaleIn = boolPointer[api.DisableScaleIn](row.DataTargetTrackingConfigurationDisableScaleIn)
	}
	if out.Data.TargetTrackingConfiguration != nil {
		if row.HasDataTargetTrackingConfigurationPredefinedMetricSpecification {
			out.Data.TargetTrackingConfiguration.PredefinedMetricSpecification = &api.PredefinedMetricSpecification{}
		}
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.PredefinedMetricSpecification != nil {
		out.Data.TargetTrackingConfiguration.PredefinedMetricSpecification.PredefinedMetricType = stringPointer[api.MetricType](row.DataTargetTrackingConfigurationPredefinedMetricSpecificationPredefinedMetricType)
	}
	if out.Data.TargetTrackingConfiguration != nil && out.Data.TargetTrackingConfiguration.PredefinedMetricSpecification != nil {
		out.Data.TargetTrackingConfiguration.PredefinedMetricSpecification.ResourceLabel = stringPointer[api.XmlStringMaxLen1023](row.DataTargetTrackingConfigurationPredefinedMetricSpecificationResourceLabel)
	}
	if out.Data.TargetTrackingConfiguration != nil {
		out.Data.TargetTrackingConfiguration.TargetValue = floatPointer[api.MetricScale](row.DataTargetTrackingConfigurationTargetValue)
	}
	return out, nil
}

func (w writer) PutPolicy(v domain.PolicyRecord) error {
	if v.Data.PredictiveScalingConfiguration != nil {
		return fmt.Errorf("autoscaling storage: unsupported PredictiveScalingConfiguration configuration")
	}
	p := sqlcgen.PutPolicyParams{
		Partition:   v.Key.Partition,
		AccountID:   v.Key.AccountID,
		Region:      v.Key.Region,
		GroupName:   v.Key.GroupKey.Name,
		Name:        v.Key.Name,
		GroupID:     v.GroupID,
		LastScaleAt: deadline(v.LastScaleAt),
	}
	p.DataAdjustmentType = nullableString(v.Data.AdjustmentType)
	p.HasDataAlarms = v.Data.Alarms != nil
	p.DataAutoScalingGroupName = nullableString(v.Data.AutoScalingGroupName)
	p.DataCooldown = nullableInt(v.Data.Cooldown)
	p.DataEnabled = nullableBool(v.Data.Enabled)
	p.DataEstimatedInstanceWarmup = nullableInt(v.Data.EstimatedInstanceWarmup)
	p.DataMetricAggregationType = nullableString(v.Data.MetricAggregationType)
	p.DataMinAdjustmentMagnitude = nullableInt(v.Data.MinAdjustmentMagnitude)
	p.DataMinAdjustmentStep = nullableInt(v.Data.MinAdjustmentStep)
	p.DataPolicyArn = nullableString(v.Data.PolicyARN)
	p.DataPolicyName = nullableString(v.Data.PolicyName)
	p.DataPolicyType = nullableString(v.Data.PolicyType)
	p.DataScalingAdjustment = nullableInt(v.Data.ScalingAdjustment)
	p.HasDataStepAdjustments = v.Data.StepAdjustments != nil
	p.HasDataTargetTrackingConfiguration = v.Data.TargetTrackingConfiguration != nil
	if v.Data.TargetTrackingConfiguration != nil {
		p.HasDataTargetTrackingConfigurationCustomizedMetricSpecification = v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		p.HasDataTargetTrackingConfigurationCustomizedMetricSpecificationDimensions = v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Dimensions != nil
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		p.DataTargetTrackingConfigurationCustomizedMetricSpecificationMetricName = nullableString(v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.MetricName)
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		p.HasDataTargetTrackingConfigurationCustomizedMetricSpecificationMetrics = v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Metrics != nil
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		p.DataTargetTrackingConfigurationCustomizedMetricSpecificationNamespace = nullableString(v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Namespace)
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		p.DataTargetTrackingConfigurationCustomizedMetricSpecificationPeriod = nullableInt(v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Period)
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		p.DataTargetTrackingConfigurationCustomizedMetricSpecificationStatistic = nullableString(v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Statistic)
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		p.DataTargetTrackingConfigurationCustomizedMetricSpecificationUnit = nullableString(v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Unit)
	}
	if v.Data.TargetTrackingConfiguration != nil {
		p.DataTargetTrackingConfigurationDisableScaleIn = nullableBool(v.Data.TargetTrackingConfiguration.DisableScaleIn)
	}
	if v.Data.TargetTrackingConfiguration != nil {
		p.HasDataTargetTrackingConfigurationPredefinedMetricSpecification = v.Data.TargetTrackingConfiguration.PredefinedMetricSpecification != nil
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.PredefinedMetricSpecification != nil {
		p.DataTargetTrackingConfigurationPredefinedMetricSpecificationPredefinedMetricType = nullableString(v.Data.TargetTrackingConfiguration.PredefinedMetricSpecification.PredefinedMetricType)
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.PredefinedMetricSpecification != nil {
		p.DataTargetTrackingConfigurationPredefinedMetricSpecificationResourceLabel = nullableString(v.Data.TargetTrackingConfiguration.PredefinedMetricSpecification.ResourceLabel)
	}
	if v.Data.TargetTrackingConfiguration != nil {
		p.DataTargetTrackingConfigurationTargetValue = nullableFloat(v.Data.TargetTrackingConfiguration.TargetValue)
	}
	policyPK, err := w.q.PutPolicy(w.ctx, p)
	if err != nil {
		return err
	}
	if err := w.putPoliciesAlarms(policyPK, v.Data.Alarms); err != nil {
		return err
	}
	if err := w.putPoliciesStepAdjustments(policyPK, v.Data.StepAdjustments); err != nil {
		return err
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		if err := w.putPoliciesDimensions(policyPK, v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Dimensions); err != nil {
			return err
		}
	} else if err := w.q.DeletePoliciesDimensions(w.ctx, policyPK); err != nil {
		return err
	}
	if v.Data.TargetTrackingConfiguration != nil && v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification != nil {
		if err := w.putPoliciesMetrics(policyPK, v.Data.TargetTrackingConfiguration.CustomizedMetricSpecification.Metrics); err != nil {
			return err
		}
	} else if err := w.q.DeletePoliciesMetrics(w.ctx, policyPK); err != nil {
		return err
	}
	return nil
}

func (r reader) readPoliciesAlarms(parentID int64) (api.Alarms, error) {
	rows, err := r.q.ListPoliciesAlarms(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.Alarms, 0, len(rows))
	for _, row := range rows {
		var item api.Alarm
		item.AlarmARN = stringPointer[api.ResourceName](row.ItemAlarmArn)
		item.AlarmName = stringPointer[api.XmlStringMaxLen255](row.ItemAlarmName)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putPoliciesAlarms(parentID int64, values api.Alarms) error {
	if err := w.q.DeletePoliciesAlarms(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertPoliciesAlarmsParams{PolicyPk: parentID, Position: int64(position)}
		p.ItemAlarmArn = nullableString(item.AlarmARN)
		p.ItemAlarmName = nullableString(item.AlarmName)
		if err := w.q.InsertPoliciesAlarms(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readPoliciesStepAdjustments(parentID int64) (api.StepAdjustments, error) {
	rows, err := r.q.ListPoliciesStepAdjustments(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.StepAdjustments, 0, len(rows))
	for _, row := range rows {
		var item api.StepAdjustment
		item.MetricIntervalLowerBound = floatPointer[api.MetricScale](row.ItemMetricIntervalLowerBound)
		item.MetricIntervalUpperBound = floatPointer[api.MetricScale](row.ItemMetricIntervalUpperBound)
		item.ScalingAdjustment = intPointer[api.PolicyIncrement](row.ItemScalingAdjustment)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putPoliciesStepAdjustments(parentID int64, values api.StepAdjustments) error {
	if err := w.q.DeletePoliciesStepAdjustments(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertPoliciesStepAdjustmentsParams{PolicyPk: parentID, Position: int64(position)}
		p.ItemMetricIntervalLowerBound = nullableFloat(item.MetricIntervalLowerBound)
		p.ItemMetricIntervalUpperBound = nullableFloat(item.MetricIntervalUpperBound)
		p.ItemScalingAdjustment = nullableInt(item.ScalingAdjustment)
		if err := w.q.InsertPoliciesStepAdjustments(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readPoliciesDimensions(parentID int64) (api.MetricDimensions, error) {
	rows, err := r.q.ListPoliciesDimensions(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.MetricDimensions, 0, len(rows))
	for _, row := range rows {
		var item api.MetricDimension
		item.Name = stringPointer[api.MetricDimensionName](row.ItemName)
		item.Value = stringPointer[api.MetricDimensionValue](row.ItemValue)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putPoliciesDimensions(parentID int64, values api.MetricDimensions) error {
	if err := w.q.DeletePoliciesDimensions(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertPoliciesDimensionsParams{PolicyPk: parentID, Position: int64(position)}
		p.ItemName = nullableString(item.Name)
		p.ItemValue = nullableString(item.Value)
		if err := w.q.InsertPoliciesDimensions(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readPoliciesMetrics(parentID int64) (api.TargetTrackingMetricDataQueries, error) {
	rows, err := r.q.ListPoliciesMetrics(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.TargetTrackingMetricDataQueries, 0, len(rows))
	for _, row := range rows {
		var item api.TargetTrackingMetricDataQuery
		item.Expression = stringPointer[api.XmlStringMaxLen2047](row.ItemExpression)
		item.Id = stringPointer[api.XmlStringMaxLen64](row.ItemID)
		item.Label = stringPointer[api.XmlStringMetricLabel](row.ItemLabel)
		if row.HasItemMetricStat {
			item.MetricStat = &api.TargetTrackingMetricStat{}
		}
		if item.MetricStat != nil {
			if row.HasItemMetricStatMetric {
				item.MetricStat.Metric = &api.Metric{}
			}
		}
		if item.MetricStat != nil && item.MetricStat.Metric != nil {
			if row.HasItemMetricStatMetricDimensions {
				var err error
				item.MetricStat.Metric.Dimensions, err = r.readPoliciesMetricsDimensions(row.ItemPk)
				if err != nil {
					return nil, err
				}
			}
		}
		if item.MetricStat != nil && item.MetricStat.Metric != nil {
			item.MetricStat.Metric.MetricName = stringPointer[api.MetricName](row.ItemMetricStatMetricMetricName)
		}
		if item.MetricStat != nil && item.MetricStat.Metric != nil {
			item.MetricStat.Metric.Namespace = stringPointer[api.MetricNamespace](row.ItemMetricStatMetricNamespace)
		}
		if item.MetricStat != nil {
			item.MetricStat.Period = intPointer[api.MetricGranularityInSeconds](row.ItemMetricStatPeriod)
		}
		if item.MetricStat != nil {
			item.MetricStat.Stat = stringPointer[api.XmlStringMetricStat](row.ItemMetricStatStat)
		}
		if item.MetricStat != nil {
			item.MetricStat.Unit = stringPointer[api.MetricUnit](row.ItemMetricStatUnit)
		}
		item.Period = intPointer[api.MetricGranularityInSeconds](row.ItemPeriod)
		item.ReturnData = boolPointer[api.ReturnData](row.ItemReturnData)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putPoliciesMetrics(parentID int64, values api.TargetTrackingMetricDataQueries) error {
	if err := w.q.DeletePoliciesMetrics(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertPoliciesMetricsParams{PolicyPk: parentID, Position: int64(position)}
		p.ItemExpression = nullableString(item.Expression)
		p.ItemID = nullableString(item.Id)
		p.ItemLabel = nullableString(item.Label)
		p.HasItemMetricStat = item.MetricStat != nil
		if item.MetricStat != nil {
			p.HasItemMetricStatMetric = item.MetricStat.Metric != nil
		}
		if item.MetricStat != nil && item.MetricStat.Metric != nil {
			p.HasItemMetricStatMetricDimensions = item.MetricStat.Metric.Dimensions != nil
		}
		if item.MetricStat != nil && item.MetricStat.Metric != nil {
			p.ItemMetricStatMetricMetricName = nullableString(item.MetricStat.Metric.MetricName)
		}
		if item.MetricStat != nil && item.MetricStat.Metric != nil {
			p.ItemMetricStatMetricNamespace = nullableString(item.MetricStat.Metric.Namespace)
		}
		if item.MetricStat != nil {
			p.ItemMetricStatPeriod = nullableInt(item.MetricStat.Period)
		}
		if item.MetricStat != nil {
			p.ItemMetricStatStat = nullableString(item.MetricStat.Stat)
		}
		if item.MetricStat != nil {
			p.ItemMetricStatUnit = nullableString(item.MetricStat.Unit)
		}
		p.ItemPeriod = nullableInt(item.Period)
		p.ItemReturnData = nullableBool(item.ReturnData)
		itemPK, err := w.q.InsertPoliciesMetrics(w.ctx, p)
		if err != nil {
			return err
		}
		if item.MetricStat == nil || item.MetricStat.Metric == nil {
			continue
		}
		if err := w.putPoliciesMetricsDimensions(itemPK, item.MetricStat.Metric.Dimensions); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) readPoliciesMetricsDimensions(parentID int64) (api.MetricDimensions, error) {
	rows, err := r.q.ListPoliciesMetricsDimensions(r.ctx, parentID)
	if err != nil {
		return nil, err
	}
	out := make(api.MetricDimensions, 0, len(rows))
	for _, row := range rows {
		var item api.MetricDimension
		item.Name = stringPointer[api.MetricDimensionName](row.ItemName)
		item.Value = stringPointer[api.MetricDimensionValue](row.ItemValue)
		out = append(out, item)
	}
	return out, nil
}

func (w writer) putPoliciesMetricsDimensions(parentID int64, values api.MetricDimensions) error {
	if err := w.q.DeletePoliciesMetricsDimensions(w.ctx, parentID); err != nil {
		return err
	}
	for position, item := range values {
		p := sqlcgen.InsertPoliciesMetricsDimensionsParams{ItemPk: parentID, Position: int64(position)}
		p.ItemName = nullableString(item.Name)
		p.ItemValue = nullableString(item.Value)
		if err := w.q.InsertPoliciesMetricsDimensions(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}
