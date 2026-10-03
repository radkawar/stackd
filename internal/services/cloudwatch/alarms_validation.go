package cloudwatch

import (
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

func alarmInvalid(message string) *awswire.Error { return failure("ValidationError", message) }

func validateAlarmName(name string) *awswire.Error {
	if !utf8.ValidString(name) {
		return alarmInvalid("AlarmName must contain valid UTF-8 characters.")
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return alarmInvalid("AlarmName must not contain ASCII Control characters")
		}
	}
	return nil
}

func alarmReference(scope Scope, text string) (AlarmKey, *awswire.Error) {
	key := AlarmKey{Scope: scope, Name: text}
	if strings.HasPrefix(text, "arn:") {
		parts := strings.SplitN(text, ":", 7)
		if len(parts) != 7 || parts[1] != scope.Partition || parts[2] != "cloudwatch" || parts[3] != scope.Region || parts[4] != scope.AccountID || parts[5] != "alarm" || parts[6] == "" {
			return key, alarmInvalid("Alarm reference must identify an alarm in the current account and Region.")
		}
		key.Name = parts[6]
	}
	if key.Name == "" {
		return key, alarmInvalid("Alarm reference must not be empty.")
	}
	return key, validateAlarmName(key.Name)
}

var alarmLambdaAction = regexp.MustCompile(`^arn:[a-z0-9-]+:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]+(?::[A-Za-z0-9_$-]+)?$`)
var alarmSNSAction = regexp.MustCompile(`^arn:[a-z0-9-]+:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,256}$`)
var alarmScalingAction = regexp.MustCompile(`^arn:[a-z0-9-]+:autoscaling:[a-z0-9-]+:[0-9]{12}:scalingPolicy:[^:]+:.+$`)

func admitAlarmActions(alarm, ok, insufficient api.ResourceList) (AlarmActions, *awswire.Error) {
	out := AlarmActions{}
	for i, list := range []api.ResourceList{alarm, ok, insufficient} {
		var admitted []string
		if list != nil {
			admitted = make([]string, 0, len(list))
		}
		for _, raw := range list {
			text := string(raw)
			parts := strings.SplitN(text, ":", 6)
			if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] == "" || parts[5] == "" || strings.ContainsAny(text, " \t\r\n") {
				return out, alarmInvalid("Invalid arn syntax: " + text)
			}
			switch parts[2] {
			case "lambda":
				if !alarmLambdaAction.MatchString(text) {
					return out, alarmInvalid("Invalid arn syntax: " + text)
				}
			case "sns":
				if strings.HasSuffix(parts[5], ".fifo") {
					return out, unsupported("CloudWatch alarm actions for FIFO SNS topics are not implemented.")
				}
				if !alarmSNSAction.MatchString(text) {
					return out, alarmInvalid("Invalid arn syntax: " + text)
				}
			case "autoscaling":
				if !alarmScalingAction.MatchString(text) {
					return out, alarmInvalid("Invalid arn syntax: " + text)
				}
			default:
				return out, unsupported("CloudWatch alarm actions for " + parts[2] + " are not implemented.")
			}
			admitted = append(admitted, text)
		}
		switch i {
		case 0:
			out.Alarm = admitted
		case 1:
			out.OK = admitted
		case 2:
			out.InsufficientData = admitted
		}
	}
	return out, nil
}

func alarmPeriod(period, count int32) *awswire.Error {
	if period < 10 || !validPeriod(int64(period)) {
		return alarmInvalid("Period must be 10, 20, 30 or a multiple of 60")
	}
	total := int64(period) * int64(count)
	if period < 3600 && total > 86400 {
		return alarmInvalid("Metrics cannot be checked across more than a day (EvaluationPeriods * Period must be <= 86400) for alarms using period < 3600")
	}
	if total > 604800 {
		return alarmInvalid("Metrics cannot be checked across more than a week (EvaluationPeriods * Period must be <= 604800) for alarms using period >= 3600")
	}
	return nil
}

// TODO: Comeback implement PromQL, anomaly, warm-up/window and query-percentile alarm engines with their actual dependencies.
func (s *Service) admitMetricAlarm(scope Scope, in *api.PutMetricAlarmInput) (*MetricAlarmConfig, *awswire.Error) {
	if in.EvaluationCriteria != nil || in.EvaluationInterval != nil {
		return nil, unsupported("CloudWatch PromQL alarm evaluation is not implemented.")
	}
	if in.WarmUpConfiguration != nil {
		return nil, unsupported("CloudWatch alarm warm-up configuration is not implemented.")
	}
	if in.EvaluationWindow != nil {
		return nil, unsupported("CloudWatch explicit alarm evaluation windows are not implemented.")
	}
	comparison := value(in.ComparisonOperator)
	if in.ThresholdMetricId != nil || slices.Contains([]string{"LessThanLowerOrGreaterThanUpperThreshold", "LessThanLowerThreshold", "GreaterThanUpperThreshold"}, comparison) {
		return nil, unsupported("CloudWatch anomaly detection alarms are not implemented.")
	}
	if !slices.Contains([]string{"GreaterThanOrEqualToThreshold", "GreaterThanThreshold", "LessThanThreshold", "LessThanOrEqualToThreshold"}, comparison) {
		return nil, alarmInvalid("PutMetricAlarm request should have a valid ComparisonOperator parameter")
	}
	if in.Threshold == nil || math.IsNaN(float64(*in.Threshold)) || math.IsInf(float64(*in.Threshold), 0) {
		return nil, alarmInvalid("PutMetricAlarm request should have valid Threshold parameter")
	}
	if in.EvaluationPeriods == nil {
		return nil, alarmInvalid("PutMetricAlarm request should have an EvaluationPeriods parameter")
	}
	config := &MetricAlarmConfig{Comparison: comparison, Threshold: float64(*in.Threshold), EvaluationPeriods: int32(*in.EvaluationPeriods), TreatMissingData: value(in.TreatMissingData), LowSampleCount: value(in.EvaluateLowSampleCountPercentile)}
	if in.DatapointsToAlarm != nil {
		if int32(*in.DatapointsToAlarm) > config.EvaluationPeriods {
			return nil, alarmInvalid("DatapointsToAlarm must be less than or equal to EvaluationPeriods")
		}
		config.DatapointsToAlarm = new(int32(*in.DatapointsToAlarm))
	}
	if in.TreatMissingData != nil && !slices.Contains([]string{"breaching", "notBreaching", "ignore", "missing"}, config.TreatMissingData) {
		return nil, alarmInvalid("Supported values for TreatMissingData are breaching, notBreaching, ignore, and missing.")
	}
	if in.EvaluateLowSampleCountPercentile != nil && !slices.Contains([]string{"evaluate", "ignore"}, config.LowSampleCount) {
		return nil, alarmInvalid("Supported options for EvaluateLowSampleCountPercentile are evaluate and ignore.")
	}
	if len(in.Metrics) != 0 {
		if in.MetricName != nil || in.Namespace != nil || in.Dimensions != nil || in.Period != nil || in.Unit != nil || in.Statistic != nil || in.ExtendedStatistic != nil {
			return nil, alarmInvalid("Scalar metric parameters must not be set if list of Metrics is set.")
		}
		if len(in.Metrics) > 20 {
			return nil, alarmInvalid("An alarm may specify at most 20 metric queries.")
		}
		metrics, expressions, returned := 0, 0, 0
		for _, query := range in.Metrics {
			admitted := AlarmMetricQuery{ID: value(query.Id), Expression: value(query.Expression), AccountID: value(query.AccountId)}
			if query.Label != nil {
				admitted.Label = new(value(query.Label))
			}
			if query.Period != nil {
				admitted.Period = new(int32(*query.Period))
				if w := alarmPeriod(*admitted.Period, config.EvaluationPeriods); w != nil {
					return nil, w
				}
			}
			if query.ReturnData != nil {
				admitted.ReturnData = new(bool(*query.ReturnData))
			}
			if admitted.ReturnData == nil || *admitted.ReturnData {
				returned++
			}
			if (query.MetricStat != nil) == (query.Expression != nil) {
				return nil, alarmInvalid("Each query must specify exactly one of MetricStat and Expression.")
			}
			if query.MetricStat != nil {
				metrics++
				stat := query.MetricStat
				if stat.Metric == nil || stat.Period == nil || stat.Stat == nil {
					return nil, alarmInvalid("MetricStat requires Metric, Period and Stat.")
				}
				key, dimensions, w := metricIdentity(scope, value(stat.Metric.Namespace), value(stat.Metric.MetricName), stat.Metric.Dimensions)
				if w != nil {
					return nil, alarmInvalid(w.Message)
				}
				if w := alarmPeriod(int32(*stat.Period), config.EvaluationPeriods); w != nil {
					return nil, w
				}
				if _, valid := parseStatistic(value(stat.Stat)); !valid {
					return nil, invalid("The value " + value(stat.Stat) + " for parameter Stat is not supported.")
				}
				admitted.Metric = &AlarmMetricStat{Key: key, Dimensions: dimensions, Period: int32(*stat.Period), Statistic: value(stat.Stat), Unit: value(stat.Unit)}
			} else {
				expressions++
			}
			config.Queries = append(config.Queries, admitted)
		}
		if metrics > 10 || expressions > 10 {
			return nil, alarmInvalid("An alarm may specify at most 10 metrics and 10 expressions.")
		}
		if returned != 1 {
			return nil, alarmInvalid("Exactly one metric query must have ReturnData set to true.")
		}
		contributors, w := validateAlarmMetricQueries(scope, config)
		if w != nil {
			return nil, w
		}
		if contributors {
			for index, actions := range []api.ResourceList{in.AlarmActions, in.OKActions, in.InsufficientDataActions} {
				for _, action := range actions {
					parts := strings.SplitN(string(action), ":", 4)
					if len(parts) != 4 {
						continue // Ordinary action admission owns ARN syntax.
					}
					if parts[2] == "autoscaling" {
						return nil, alarmInvalid("Autoscaling actions are not available for Multi Time Series alarms")
					}
					if index == 2 && (parts[2] == "sns" || parts[2] == "lambda") {
						return nil, alarmInvalid("InsufficientData actions are not supported for contributor-level action types in Multi Time Series alarms")
					}
				}
			}
		}
		if config.LowSampleCount != "" {
			return nil, unsupported("CloudWatch metric-query percentile low-sample evaluation is not implemented.")
		}
	} else {
		if in.Statistic != nil && in.ExtendedStatistic != nil {
			return nil, alarmInvalid("PutMetricAlarm request can not be made with both Statistic and ExtendedStatistic parameters. Only one of them should be present")
		}
		statistic := value(in.Statistic)
		if in.ExtendedStatistic != nil {
			statistic = value(in.ExtendedStatistic)
		}
		if statistic == "" {
			return nil, alarmInvalid("PutMetricAlarm request should have a Statistic parameter")
		}
		if _, valid := parseStatistic(statistic); !valid {
			return nil, invalid("The value " + statistic + " for parameter ExtendedStatistic is not supported.")
		}
		if config.LowSampleCount != "" && !strings.HasPrefix(statistic, "p") {
			return nil, alarmInvalid("Option evaluateLowSampleCountPercentile can not be applied with statistic " + statistic + ". This option is enabled only for percentile statistics.")
		}
		if in.Period == nil {
			return nil, alarmInvalid("PutMetricAlarm request should have a Period parameter")
		}
		if w := alarmPeriod(int32(*in.Period), config.EvaluationPeriods); w != nil {
			return nil, w
		}
		key, dimensions, w := metricIdentity(scope, value(in.Namespace), value(in.MetricName), in.Dimensions)
		if w != nil {
			return nil, alarmInvalid(w.Message)
		}
		config.Metric = &AlarmMetricStat{Key: key, Dimensions: dimensions, Period: int32(*in.Period), Statistic: statistic, Unit: value(in.Unit)}
	}
	return config, nil
}

// Compare public configuration, not generated query IDs or derived dependency
// and dimension caches. Admission has already enforced the same alarm kind.
func equalAlarmConfiguration(a, b AlarmRecord) bool {
	if a.ActionsEnabled != b.ActionsEnabled || !equalAlarmOptional(a.Description, b.Description) ||
		!slices.Equal(a.Actions.Alarm, b.Actions.Alarm) || !slices.Equal(a.Actions.OK, b.Actions.OK) ||
		!slices.Equal(a.Actions.InsufficientData, b.Actions.InsufficientData) {
		return false
	}
	if a.Composite != nil {
		x, y := a.Composite, b.Composite
		return x.Rule == y.Rule && x.Suppressor == y.Suppressor && x.WaitPeriod == y.WaitPeriod && x.ExtensionPeriod == y.ExtensionPeriod
	}
	x, y := a.Metric, b.Metric
	if x.Comparison != y.Comparison || x.Threshold != y.Threshold || x.EvaluationPeriods != y.EvaluationPeriods ||
		!equalAlarmOptional(x.DatapointsToAlarm, y.DatapointsToAlarm) || x.TreatMissingData != y.TreatMissingData ||
		x.LowSampleCount != y.LowSampleCount || !equalAlarmMetric(x.Metric, y.Metric) {
		return false
	}
	return slices.EqualFunc(x.Queries, y.Queries, func(a, b AlarmMetricQuery) bool {
		return a.ID == b.ID && a.Expression == b.Expression && a.AccountID == b.AccountID &&
			equalAlarmOptional(a.Label, b.Label) && equalAlarmOptional(a.Period, b.Period) &&
			equalAlarmOptional(a.ReturnData, b.ReturnData) && equalAlarmMetric(a.Metric, b.Metric)
	})
}

func equalAlarmMetric(a, b *AlarmMetricStat) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Key == b.Key && a.Period == b.Period && a.Statistic == b.Statistic && a.Unit == b.Unit
}

func equalAlarmOptional[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
