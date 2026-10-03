package autoscaling

import (
	"math"
	"slices"

	api "stackd/internal/awsapi/autoscaling"
)

func finiteMetric(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func validatePolicy(p api.ScalingPolicy) error {
	kind := value(p.PolicyType)
	if kind != "SimpleScaling" && kind != "StepScaling" && kind != "TargetTrackingScaling" {
		return invalid("PolicyType must be SimpleScaling, StepScaling, or TargetTrackingScaling")
	}
	if p.Cooldown != nil && *p.Cooldown < 0 || p.EstimatedInstanceWarmup != nil && *p.EstimatedInstanceWarmup < 0 {
		return invalid("Cooldown and EstimatedInstanceWarmup must not be negative")
	}
	if kind == "TargetTrackingScaling" {
		if p.AdjustmentType != nil || p.ScalingAdjustment != nil || len(p.StepAdjustments) > 0 || p.Cooldown != nil || p.MinAdjustmentMagnitude != nil || p.MinAdjustmentStep != nil {
			return invalid("Adjustment fields and Cooldown are not valid for target tracking policies")
		}
		return validateTracking(p.TargetTrackingConfiguration)
	}
	if p.TargetTrackingConfiguration != nil {
		return invalid("TargetTrackingConfiguration requires TargetTrackingScaling")
	}
	switch value(p.AdjustmentType) {
	case "ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity":
	default:
		return invalid("AdjustmentType must be ChangeInCapacity, ExactCapacity, or PercentChangeInCapacity")
	}
	if p.MinAdjustmentMagnitude != nil && *p.MinAdjustmentMagnitude <= 0 || p.MinAdjustmentStep != nil && *p.MinAdjustmentStep <= 0 {
		return invalid("Minimum adjustment must be positive")
	}
	if (p.MinAdjustmentMagnitude != nil || p.MinAdjustmentStep != nil) && value(p.AdjustmentType) != "PercentChangeInCapacity" {
		return invalid("Minimum adjustment is valid only with PercentChangeInCapacity")
	}
	if p.MinAdjustmentMagnitude != nil && p.MinAdjustmentStep != nil && int32(*p.MinAdjustmentMagnitude) != int32(*p.MinAdjustmentStep) {
		return invalid("MinAdjustmentStep and MinAdjustmentMagnitude must agree")
	}
	if kind == "SimpleScaling" {
		if p.ScalingAdjustment == nil {
			return invalid("ScalingAdjustment is required for SimpleScaling")
		}
		if value(p.AdjustmentType) == "ExactCapacity" && *p.ScalingAdjustment < 0 {
			return invalid("ExactCapacity must not be negative")
		}
		if len(p.StepAdjustments) > 0 || p.MetricAggregationType != nil || p.EstimatedInstanceWarmup != nil {
			return invalid("Step scaling fields cannot be used with SimpleScaling")
		}
		return nil
	}
	if p.ScalingAdjustment != nil || p.Cooldown != nil {
		return invalid("ScalingAdjustment and Cooldown cannot be used with StepScaling")
	}
	if value(p.MetricAggregationType) != "Average" && value(p.MetricAggregationType) != "Minimum" && value(p.MetricAggregationType) != "Maximum" {
		return invalid("MetricAggregationType must be Average, Minimum, or Maximum")
	}
	return validateSteps(p.StepAdjustments, value(p.AdjustmentType))
}

func validateSteps(steps api.StepAdjustments, adjustment string) error {
	if len(steps) < 1 || len(steps) > 20 {
		return invalid("StepAdjustments must contain between 1 and 20 adjustments")
	}
	ordered := slices.Clone(steps)
	lower := func(s api.StepAdjustment) float64 {
		if s.MetricIntervalLowerBound == nil {
			return math.Inf(-1)
		}
		return float64(*s.MetricIntervalLowerBound)
	}
	slices.SortFunc(ordered, func(a, b api.StepAdjustment) int {
		if lower(a) < lower(b) {
			return -1
		}
		if lower(a) > lower(b) {
			return 1
		}
		return 0
	})
	var previousUpper float64
	for i, step := range ordered {
		if step.ScalingAdjustment == nil || adjustment == "ExactCapacity" && *step.ScalingAdjustment < 0 {
			return invalid("Every step requires a valid ScalingAdjustment")
		}
		if step.MetricIntervalLowerBound == nil && step.MetricIntervalUpperBound == nil {
			return invalid("A step must specify at least one interval bound")
		}
		lo, hi := lower(step), math.Inf(1)
		if step.MetricIntervalLowerBound != nil && !finiteMetric(lo) {
			return invalid("Step bounds must be finite")
		}
		if step.MetricIntervalUpperBound != nil {
			hi = float64(*step.MetricIntervalUpperBound)
			if !finiteMetric(hi) {
				return invalid("Step bounds must be finite")
			}
		}
		if lo >= hi {
			return invalid("The step lower bound must be less than its upper bound")
		}
		if i > 0 && lo != previousUpper {
			return invalid("Step intervals must not overlap or have gaps")
		}
		previousUpper = hi
	}
	if lower(ordered[0]) < 0 && ordered[0].MetricIntervalLowerBound != nil {
		return invalid("Negative step intervals require an unbounded lower interval")
	}
	if previousUpper > 0 && ordered[len(ordered)-1].MetricIntervalUpperBound != nil {
		return invalid("Positive step intervals require an unbounded upper interval")
	}
	return nil
}

// Percent changes round toward zero, with at least one instance (or the
// requested magnitude) when the percentage is nonzero. Calculations remain
// floating-point until bounds are applied, avoiding int32 overflow.
func adjustedCapacity(base int32, adjustment int32, kind string, magnitude int32) float64 {
	switch kind {
	case "ExactCapacity":
		return float64(adjustment)
	case "PercentChangeInCapacity":
		delta := math.Trunc(float64(base) * float64(adjustment) / 100)
		if adjustment != 0 && math.Abs(delta) < float64(max(magnitude, 1)) {
			delta = math.Copysign(float64(max(magnitude, 1)), float64(adjustment))
		}
		return float64(base) + delta
	default:
		return float64(base) + float64(adjustment)
	}
}
func policyMagnitude(p api.ScalingPolicy) int32 {
	if p.MinAdjustmentMagnitude != nil {
		return int32(*p.MinAdjustmentMagnitude)
	}
	if p.MinAdjustmentStep != nil {
		return int32(*p.MinAdjustmentStep)
	}
	return 1
}
func stepCapacity(p api.ScalingPolicy, base int32, metric, threshold float64) (float64, bool) {
	difference := metric - threshold
	for _, step := range p.StepAdjustments {
		lo, hi := math.Inf(-1), math.Inf(1)
		if step.MetricIntervalLowerBound != nil {
			lo = float64(*step.MetricIntervalLowerBound)
		}
		if step.MetricIntervalUpperBound != nil {
			hi = float64(*step.MetricIntervalUpperBound)
		}
		matches := difference >= lo && difference < hi
		if difference < 0 {
			matches = difference > lo && difference <= hi
		}
		if matches {
			return adjustedCapacity(base, int32(*step.ScalingAdjustment), value(p.AdjustmentType), policyMagnitude(p)), true
		}
	}
	return 0, false
}
func trackingCapacity(base int32, metric, target float64) float64 {
	if base == 0 {
		if metric > 0 {
			return 1
		}
		return 0
	}
	ratio := metric / target
	// Capacities are int32. Saturate before multiplying, so finite metrics
	// with very different units cannot overflow before the group bound applies.
	if ratio >= float64(math.MaxInt32)/float64(base) {
		return float64(math.MaxInt32)
	}
	return math.Ceil(float64(base) * ratio)
}
