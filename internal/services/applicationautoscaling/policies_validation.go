package applicationautoscaling

import (
	"cmp"
	"context"
	"math"
	"reflect"
	"slices"
	"strings"

	api "stackd/internal/awsapi/applicationautoscaling"
)

func mergeStepPolicy(previous, update *api.StepScalingPolicyConfiguration) (*api.StepScalingPolicyConfiguration, error) {
	if update == nil {
		if previous == nil {
			return nil, invalid("StepScalingPolicyConfiguration must be specified")
		}
		return previous, nil
	}
	config := api.CloneStepScalingPolicyConfiguration(*update)
	// A supplied configuration replaces optional fields, but required values
	// omitted on update retain their existing values. Nil/null retains all.
	if previous != nil {
		if config.AdjustmentType == nil {
			config.AdjustmentType = previous.AdjustmentType
		}
		if config.StepAdjustments == nil {
			config.StepAdjustments = previous.StepAdjustments
		}
	}
	if config.AdjustmentType == nil {
		return nil, invalid("AdjustmentType must be specified")
	}
	if config.Cooldown != nil && *config.Cooldown < 0 {
		return nil, invalid("Cooldown cannot be negative")
	}
	if config.MinAdjustmentMagnitude != nil && (*config.MinAdjustmentMagnitude <= 0 || *config.AdjustmentType != api.AdjustmentTypePercentChangeInCapacity) {
		return nil, invalid("MinAdjustmentMagnitude requires PercentChangeInCapacity and a positive value")
	}
	if len(config.StepAdjustments) == 0 {
		return nil, invalid("At least one step adjustment must be specified")
	}
	// Preserve the caller's serialized order while checking the union of its
	// intervals. Each interval is open at the side away from the threshold.
	intervals := slices.Clone(config.StepAdjustments)
	slices.SortFunc(intervals, func(a, b api.StepAdjustment) int { return cmp.Compare(stepLower(a), stepLower(b)) })
	for i, step := range intervals {
		if step.MetricIntervalLowerBound == nil && step.MetricIntervalUpperBound == nil {
			return nil, invalid("A step must specify at least one interval bound")
		}
		lower, upper := stepLower(step), stepUpper(step)
		if lower >= upper {
			return nil, invalid("Step upper bound must exceed its lower bound")
		}
		if i > 0 && stepUpper(intervals[i-1]) != lower {
			return nil, invalid("Step adjustment intervals cannot overlap or have a gap")
		}
		if *config.AdjustmentType == api.AdjustmentTypeExactCapacity && *step.ScalingAdjustment < 0 {
			return nil, invalid("ExactCapacity cannot specify negative capacity")
		}
	}
	if lower := stepLower(intervals[0]); lower < 0 && !math.IsInf(lower, -1) {
		return nil, invalid("Negative intervals must extend to a null lower bound")
	}
	if upper := stepUpper(intervals[len(intervals)-1]); upper > 0 && !math.IsInf(upper, 1) {
		return nil, invalid("Positive intervals must extend to a null upper bound")
	}
	return &config, nil
}

func stepLower(step api.StepAdjustment) float64 {
	if step.MetricIntervalLowerBound == nil {
		return math.Inf(-1)
	}
	return float64(*step.MetricIntervalLowerBound)
}

func stepUpper(step api.StepAdjustment) float64 {
	if step.MetricIntervalUpperBound == nil {
		return math.Inf(1)
	}
	return float64(*step.MetricIntervalUpperBound)
}

func mergeTrackingPolicy(previous, update *api.TargetTrackingScalingPolicyConfiguration) (*api.TargetTrackingScalingPolicyConfiguration, error) {
	if update == nil {
		if previous == nil {
			return nil, invalid("TargetTrackingScalingPolicyConfiguration must be specified")
		}
		return previous, nil
	}
	config := api.CloneTargetTrackingScalingPolicyConfiguration(*update)
	if previous != nil && config.PredefinedMetricSpecification == nil && config.CustomizedMetricSpecification == nil {
		config.PredefinedMetricSpecification = previous.PredefinedMetricSpecification
		config.CustomizedMetricSpecification = previous.CustomizedMetricSpecification
	}
	if config.TargetValue == nil || *config.TargetValue <= 0 {
		return nil, invalid("TargetValue must be greater than zero")
	}
	if config.ScaleInCooldown != nil && *config.ScaleInCooldown < 0 || config.ScaleOutCooldown != nil && *config.ScaleOutCooldown < 0 {
		return nil, invalid("Cooldown cannot be negative")
	}
	if (config.PredefinedMetricSpecification == nil) == (config.CustomizedMetricSpecification == nil) {
		return nil, invalid("Specify exactly one predefined or customized metric")
	}
	if predefined := config.PredefinedMetricSpecification; predefined != nil {
		switch value(predefined.PredefinedMetricType) {
		case "ECSServiceAverageCPUUtilization", "ECSServiceAverageMemoryUtilization", "ECSServiceAverageCPUUtilizationHighResolution", "ECSServiceAverageMemoryUtilizationHighResolution", "DynamoDBReadCapacityUtilization", "DynamoDBWriteCapacityUtilization":
			if predefined.ResourceLabel != nil {
				return nil, invalid("ResourceLabel is only supported for ALBRequestCountPerTarget")
			}
		case "ALBRequestCountPerTarget":
			if value(predefined.ResourceLabel) == "" {
				return nil, invalid("Resource label should be specified for predefined metric type ALBRequestCountPerTarget")
			}
			if _, _, ok := albResourceLabel(value(predefined.ResourceLabel)); !ok {
				return nil, invalid("Invalid resource label '" + value(predefined.ResourceLabel) + "' for predefined metric type ALBRequestCountPerTarget")
			}
		default:
			return nil, invalid("The predefined metric is not supported for this scalable dimension")
		}
	}
	if custom := config.CustomizedMetricSpecification; custom != nil {
		if custom.Metrics != nil {
			if len(custom.Metrics) == 0 || custom.MetricName != nil || custom.Namespace != nil || custom.Statistic != nil || custom.Unit != nil || len(custom.Dimensions) != 0 {
				return nil, invalid("Metric math cannot be combined with a single metric specification")
			}
			// CloudWatch owns expression, dimension and statistic validation when
			// the managed alarms are admitted in this same transaction.
			for i := range custom.Metrics {
				query := &custom.Metrics[i]
				if query.Label != nil && *query.Label == "" {
					return nil, invalid("Metric query Label must not be empty")
				}
				if query.ReturnData == nil {
					query.ReturnData = new(api.ReturnData(true))
				}
				if query.MetricStat != nil && query.MetricStat.Metric != nil && query.MetricStat.Metric.Dimensions == nil {
					query.MetricStat.Metric.Dimensions = api.TargetTrackingMetricDimensions{}
				}
			}
		} else if value(custom.MetricName) == "" || value(custom.Namespace) == "" || custom.Statistic == nil {
			return nil, invalid("A customized metric requires MetricName, Namespace and Statistic")
		}
		if custom.Dimensions == nil {
			custom.Dimensions = api.MetricDimensions{}
		}
	}
	return &config, nil
}

func (s *Service) validateTrackingMetric(ctx context.Context, tx Transaction, key PolicyKey, config *api.TargetTrackingScalingPolicyConfiguration) error {
	if s.alarms == nil || s.identity == nil {
		return unsupported("Target tracking requires CloudWatch and its scaling service identity")
	}
	if predefined := config.PredefinedMetricSpecification; predefined != nil {
		metricType := value(predefined.PredefinedMetricType)
		if key.Namespace == "dynamodb" {
			expected := "DynamoDBWriteCapacityUtilization"
			if strings.HasSuffix(key.Dimension, ":ReadCapacityUnits") {
				expected = "DynamoDBReadCapacityUtilization"
			}
			if metricType != expected {
				return invalid("The predefined metric is not supported for this scalable dimension")
			}
			if *config.TargetValue < 20 || *config.TargetValue > 90 {
				return invalid("DynamoDB target utilization must be between 20 and 90 percent")
			}
		} else if strings.HasPrefix(metricType, "DynamoDB") {
			return invalid("The predefined metric is not supported for this scalable dimension")
		}
		if metricType == "ALBRequestCountPerTarget" {
			if s.resources == nil {
				return unsupported("ALB target tracking requires the ECS resource owner")
			}
			service, err := s.identity.Context(ctx, key.TargetKey, "AutoScaling-ValidateScalingPolicy")
			if err != nil {
				return err
			}
			_, group, _ := albResourceLabel(value(predefined.ResourceLabel))
			attached, err := s.resources.ALBTargetGroupAttached(service, key.TargetKey, group)
			if err != nil {
				return err
			}
			if !attached {
				return invalid("Target group " + group + " is not attached to resource " + key.ResourceID)
			}
		}
		name, period := trackingPredefinedMetric(predefined)
		if period == 20 {
			if s.resources == nil {
				return unsupported("High-resolution target tracking requires the resource metric producer")
			}
			service, err := s.identity.Context(ctx, key.TargetKey, "AutoScaling-ValidateScalingPolicy")
			if err != nil {
				return err
			}
			ready, err := s.resources.HighResolutionReady(service, key.TargetKey, name)
			if err != nil {
				return err
			}
			if !ready {
				return invalid("High-resolution metrics are not fully enabled on the ECS service.")
			}
		}
	}
	policies, err := tx.Policies(PolicyQuery{Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension})
	if err != nil {
		return err
	}
	for _, policy := range policies {
		if policy.Key != key && sameTrackingMetric(config, policy.Data.TargetTrackingScalingPolicyConfiguration) {
			return invalid("Only one TargetTrackingScaling policy for a given metric specification is allowed.")
		}
	}
	return nil
}

// Metric ownership excludes the target value and scaling controls. Scalar custom
// metrics and sole MetricStat queries share a primitive identity; other query
// collections retain their nested configuration and ignore only outer order.
func sameTrackingMetric(config, previous *api.TargetTrackingScalingPolicyConfiguration) bool {
	if previous == nil {
		return false
	}
	if predefined := config.PredefinedMetricSpecification; predefined != nil {
		return previous.PredefinedMetricSpecification != nil &&
			value(predefined.PredefinedMetricType) == value(previous.PredefinedMetricSpecification.PredefinedMetricType) &&
			value(predefined.ResourceLabel) == value(previous.PredefinedMetricSpecification.ResourceLabel)
	}
	custom, prior := config.CustomizedMetricSpecification, previous.CustomizedMetricSpecification
	if custom == nil || prior == nil {
		return false
	}
	metric, primitive := trackingPrimitiveMetric(custom)
	priorMetric, priorPrimitive := trackingPrimitiveMetric(prior)
	if primitive || priorPrimitive {
		return primitive && priorPrimitive && metric.equal(priorMetric)
	}
	// Admission has already defaulted ReturnData. Do not infer expression
	// equivalence or custom-period identity beyond the measured query structure.
	if len(custom.Metrics) != len(prior.Metrics) {
		return false
	}
	for _, query := range custom.Metrics {
		if !slices.ContainsFunc(prior.Metrics, func(candidate api.TargetTrackingMetricDataQuery) bool {
			return reflect.DeepEqual(query, candidate)
		}) {
			return false
		}
	}
	return true
}

// The two API dimension types stay as borrowed slices: identity comparison must
// neither rewrite the stored configuration nor copy it into a canonical form.
type trackingPrimitive struct {
	namespace       string
	name            string
	statistic       string
	dimensions      api.MetricDimensions
	queryDimensions api.TargetTrackingMetricDimensions
}

func trackingPrimitiveMetric(custom *api.CustomizedMetricSpecification) (trackingPrimitive, bool) {
	if custom.Metrics == nil {
		return trackingPrimitive{
			namespace:  value(custom.Namespace),
			name:       value(custom.MetricName),
			statistic:  value(custom.Statistic),
			dimensions: custom.Dimensions,
		}, true
	}
	if len(custom.Metrics) != 1 {
		return trackingPrimitive{}, false
	}
	query := &custom.Metrics[0]
	if query.Expression != nil || query.MetricStat == nil || query.MetricStat.Metric == nil {
		return trackingPrimitive{}, false
	}
	stat := query.MetricStat
	return trackingPrimitive{
		namespace:       value(stat.Metric.Namespace),
		name:            value(stat.Metric.MetricName),
		statistic:       value(stat.Stat),
		queryDimensions: stat.Metric.Dimensions,
	}, true
}

func (m trackingPrimitive) dimension(index int) (string, string) {
	if m.dimensions != nil {
		dimension := m.dimensions[index]
		return value(dimension.Name), value(dimension.Value)
	}
	dimension := m.queryDimensions[index]
	return value(dimension.Name), value(dimension.Value)
}

func (m trackingPrimitive) equal(other trackingPrimitive) bool {
	count := len(m.dimensions) + len(m.queryDimensions)
	if m.namespace != other.namespace || m.name != other.name || m.statistic != other.statistic ||
		count != len(other.dimensions)+len(other.queryDimensions) {
		return false
	}
	for i := range count {
		name, value := m.dimension(i)
		ownCount, otherCount := 0, 0
		for j := range count {
			if candidateName, candidateValue := m.dimension(j); name == candidateName && value == candidateValue {
				ownCount++
			}
			if candidateName, candidateValue := other.dimension(j); name == candidateName && value == candidateValue {
				otherCount++
			}
		}
		if ownCount != otherCount {
			return false
		}
	}
	return true
}

// Native admission checks the current ECS target binding, not load-balancer
// existence. A stale but well-shaped LB label is accepted and receives no data.
func albResourceLabel(label string) (string, string, bool) {
	parts := strings.Split(label, "/")
	if len(parts) != 6 || parts[0] != "app" || parts[3] != "targetgroup" {
		return "", "", false
	}
	for _, part := range parts {
		if part == "" {
			return "", "", false
		}
	}
	return strings.Join(parts[:3], "/"), strings.Join(parts[3:], "/"), true
}
