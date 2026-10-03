package applicationautoscaling

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/internal/services/cloudwatch"
)

type alarmSignal struct {
	values    []float64
	threshold float64
	below     bool
}

func decodeAlarmSignal(input cloudwatch.ScalingAlarmSignal, now time.Time) (alarmSignal, error) {
	// A struct decoder would incorrectly accept PascalCase names. Native actions
	// require recentDatapoints; evaluatedDatapoints is not a substitute.
	var fields map[string]json.RawMessage
	var signal alarmSignal
	if err := json.Unmarshal([]byte(input.ReasonData), &fields); err != nil {
		return signal, invalid("Metric data points must be provided")
	}
	points := fields["recentDatapoints"]
	if bytes.Contains(points, []byte("null")) || json.Unmarshal(points, &signal.values) != nil || len(signal.values) == 0 {
		return signal, invalid("Metric data points must be provided")
	}
	threshold := fields["threshold"]
	if bytes.Contains(threshold, []byte("null")) || json.Unmarshal(threshold, &signal.threshold) != nil {
		return signal, invalid("A numeric alarm threshold must be provided")
	}
	var date string
	if json.Unmarshal(fields["queryDate"], &date) != nil {
		return signal, invalid("The alarm query timestamp must be provided")
	}
	queried, err := time.Parse(time.RFC3339Nano, date)
	if err != nil {
		queried, err = time.Parse("2006-01-02T15:04:05.999999999-0700", date)
	}
	// Native observations accept an age of 5.743s and reject 15.603s. Ten
	// seconds is the local cutoff within that bracket, not a proven AWS limit.
	// TODO: Comeback establish the native freshness cutoff beyond this bracket.
	if err != nil || now.Sub(queried) > 10*time.Second {
		return signal, invalid("Scaling deemed unsafe because the alarm query timestamp is outdated")
	}
	signal.below = strings.HasPrefix(input.Comparison, "LessThan")
	return signal, nil
}

func aggregateSignal(values []float64, statistic string) float64 {
	result := values[0]
	for _, value := range values[1:] {
		switch statistic {
		case "Minimum":
			result = min(result, value)
		case "Maximum":
			result = max(result, value)
		default:
			result += value
		}
	}
	if statistic != "Minimum" && statistic != "Maximum" {
		result /= float64(len(values))
	}
	return result
}

func stepCapacity(config *api.StepScalingPolicyConfiguration, running int32, signal alarmSignal) (float64, bool, error) {
	metric := aggregateSignal(signal.values, value(config.MetricAggregationType))
	if math.IsInf(metric, 0) {
		return 0, false, invalid("The aggregated metric is not finite")
	}
	difference := metric - signal.threshold
	for _, step := range config.StepAdjustments {
		lower, upper := math.Inf(-1), math.Inf(1)
		if step.MetricIntervalLowerBound != nil {
			lower = float64(*step.MetricIntervalLowerBound)
		}
		if step.MetricIntervalUpperBound != nil {
			upper = float64(*step.MetricIntervalUpperBound)
		}
		matches := difference >= lower && difference < upper
		if signal.below {
			matches = difference > lower && difference <= upper
		}
		if !matches {
			continue
		}
		adjustment := float64(*step.ScalingAdjustment)
		switch value(config.AdjustmentType) {
		case "ExactCapacity":
			return adjustment, true, nil
		case "PercentChangeInCapacity":
			change := math.Trunc(float64(running) * adjustment / 100)
			minimum := 1.0
			if config.MinAdjustmentMagnitude != nil {
				minimum = float64(*config.MinAdjustmentMagnitude)
			}
			if adjustment != 0 && math.Abs(change) < minimum {
				change = math.Copysign(minimum, adjustment)
			}
			return float64(running) + change, true, nil
		default:
			return float64(running) + adjustment, true, nil
		}
	}
	return 0, false, nil
}

func trackingCapacity(config *api.TargetTrackingScalingPolicyConfiguration, running int32, metric float64) float64 {
	if running == 0 {
		if metric > float64(*config.TargetValue) {
			return 1
		}
		return 0
	}
	return math.Ceil(float64(running) * metric / float64(*config.TargetValue))
}

func boundedCapacity(target TargetRecord, proposed float64) int32 {
	return int32(min(max(proposed, float64(*target.Data.MinCapacity)), float64(*target.Data.MaxCapacity)))
}

func scaleInDisabled(policy PolicyRecord) bool {
	config := policy.Data.TargetTrackingScalingPolicyConfiguration
	return config != nil && config.DisableScaleIn != nil && bool(*config.DisableScaleIn)
}

func policyCooldown(policy PolicyRecord, scaleOut bool) time.Duration {
	seconds := int32(300)
	if policy.Key.Namespace == "dynamodb" {
		seconds = 0
	}
	if config := policy.Data.StepScalingPolicyConfiguration; config != nil && config.Cooldown != nil {
		seconds = int32(*config.Cooldown)
	}
	if config := policy.Data.TargetTrackingScalingPolicyConfiguration; config != nil {
		cooldown := config.ScaleInCooldown
		if scaleOut {
			cooldown = config.ScaleOutCooldown
		}
		if cooldown != nil {
			seconds = int32(*cooldown)
		}
	}
	return time.Duration(seconds) * time.Second
}
