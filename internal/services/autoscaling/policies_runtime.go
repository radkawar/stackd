package autoscaling

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudwatch"
)

// ApplyAlarm is an internal CloudWatch action boundary. A public ExecutePolicy
// call cannot manufacture a target tracking event or impersonate its source.
func (s *Service) ApplyAlarm(ctx context.Context, policyARN string, input cloudwatch.ScalingAlarmSignal) *awswire.Error {
	metadata := awsctx.FromContext(ctx)
	scope := scopeFor(ctx)
	source, err := arn.Parse(metadata.ServicePrincipal.SourceARN)
	if metadata.ServicePrincipal.Name != "cloudwatch.amazonaws.com" || err != nil || source.Service != "cloudwatch" || source.Partition != scope.Partition || source.AccountID != scope.AccountID || source.Region != scope.Region || !strings.HasPrefix(source.Resource, "alarm:") {
		return &awswire.Error{Code: "AccessDenied", Message: "A scoped CloudWatch alarm delivery is required", StatusCode: 403}
	}
	resource, err := arn.Parse(policyARN)
	if err != nil || resource.Service != "autoscaling" || resource.Partition != scope.Partition || resource.AccountID != scope.AccountID || resource.Region != scope.Region || !strings.HasPrefix(resource.Resource, "scalingPolicy:") {
		return invalid("Policy not found")
	}
	_, suffix, ok := strings.Cut(resource.Resource, ":autoScalingGroupName/")
	if !ok {
		return invalid("Policy not found")
	}
	group, name, ok := strings.Cut(suffix, ":policyName/")
	if !ok {
		return invalid("Policy not found")
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		g, err := tx.Group(GroupKey{Scope: scope, Name: group})
		if errors.Is(err, ErrNotFound) {
			return invalid("Auto Scaling group not found")
		}
		if err != nil {
			return err
		}
		p, err := tx.Policy(PolicyKey{GroupKey: g.Key, Name: name})
		if errors.Is(err, ErrNotFound) || err == nil && (p.GroupID != g.ID || value(p.Data.PolicyARN) != policyARN) {
			return invalid("Policy not found")
		}
		if err != nil {
			return err
		}
		if processSuspended(g, "AlarmNotification") {
			return nil
		}
		if value(p.Data.PolicyType) == "TargetTrackingScaling" {
			managed := false
			for _, a := range p.Data.Alarms {
				if value(a.AlarmARN) == metadata.ServicePrincipal.SourceARN {
					managed = true
					break
				}
			}
			if !managed {
				return invalid("The alarm is not managed by this target tracking policy")
			}
		}
		metric, threshold, err := alarmMeasurement(input, value(p.Data.MetricAggregationType), s.clock.Now())
		if err != nil && value(p.Data.PolicyType) != "SimpleScaling" {
			return err
		}
		if value(p.Data.PolicyType) == "TargetTrackingScaling" {
			target := float64(*p.Data.TargetTrackingConfiguration.TargetValue)
			if strings.HasPrefix(input.Comparison, "LessThan") {
				if metric >= target*0.9 || int32(*g.Data.DesiredCapacity) == 0 {
					return nil
				}
			} else if metric <= target {
				return nil
			}
		}
		return s.applyScalingPolicy(tx.Context(), tx, g, p, new(api.MetricScale(metric)), new(api.MetricScale(threshold)), true, true)
	})
	if err == nil {
		s.jobs.Wake()
		return nil
	}
	return wireError(err)
}

func alarmMeasurement(signal cloudwatch.ScalingAlarmSignal, statistic string, now time.Time) (float64, float64, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(signal.ReasonData), &fields) != nil {
		return 0, 0, invalid("Metric data points must be provided")
	}
	var points []float64
	var threshold float64
	var queryDate string
	if bytes.Contains(fields["recentDatapoints"], []byte("null")) || json.Unmarshal(fields["recentDatapoints"], &points) != nil || len(points) == 0 || json.Unmarshal(fields["threshold"], &threshold) != nil || string(fields["threshold"]) == "null" || !finiteMetric(threshold) {
		return 0, 0, invalid("Finite metric data points and a threshold must be provided")
	}
	if json.Unmarshal(fields["queryDate"], &queryDate) != nil {
		return 0, 0, invalid("An alarm query timestamp must be provided")
	}
	queried, err := time.Parse(time.RFC3339Nano, queryDate)
	if err != nil {
		queried, err = time.Parse("2006-01-02T15:04:05.999999999-0700", queryDate)
	}
	if err != nil || queried.After(now.Add(time.Minute)) || now.Sub(queried) > 5*time.Minute {
		return 0, 0, invalid("The alarm metric query is not current")
	}
	result := points[0]
	for i, v := range points {
		if !finiteMetric(v) {
			return 0, 0, invalid("Metric data points must be finite")
		}
		if i == 0 {
			continue
		}
		switch statistic {
		case "Minimum":
			result = min(result, v)
		case "Maximum":
			result = max(result, v)
		default:
			result += v
		}
	}
	if statistic != "Minimum" && statistic != "Maximum" {
		result /= float64(len(points))
	}
	if !finiteMetric(result) {
		return 0, 0, invalid("The aggregated metric must be finite")
	}
	return result, threshold, nil
}

func (s *Service) applyScalingPolicy(ctx context.Context, tx Transaction, g GroupRecord, p PolicyRecord, metric, threshold *api.MetricScale, honorCooldown, alarm bool) error {
	if g.Deleting {
		return failure("ResourceInUse", "The Auto Scaling group is being deleted")
	}
	if p.Data.Enabled != nil && !bool(*p.Data.Enabled) {
		return nil
	}
	if s.identity == nil {
		return unsupported("Auto Scaling execution identity is unavailable")
	}
	service, err := s.identity.Context(ctx, g)
	if err != nil {
		return err
	}
	now := s.clock.Now()
	desired := int32(*g.Data.DesiredCapacity)
	base := desired
	kind := value(p.Data.PolicyType)
	instances, err := tx.Instances(g.Key)
	if err != nil {
		return err
	}
	warming, current := int32(0), int32(0)
	for _, instance := range instances {
		if instance.GroupID != g.ID {
			continue
		}
		state := value(instance.Data.LifecycleState)
		switch {
		case strings.HasPrefix(state, "Pending"):
			warming++
		case state == "InService":
			if now.Before(instance.WarmUntil) {
				warming++
			} else {
				current++
			}
		case strings.HasPrefix(state, "Terminating") && !instance.InServiceAt.IsZero():
			current++
		}
	}
	// Desired capacity already includes launches not yet admitted by EC2.
	// Count that pending work too, so repeated identical breaches add no more.
	warming = max(warming, desired-current)
	if kind != "SimpleScaling" {
		base = current
	}
	var proposed float64
	switch kind {
	case "SimpleScaling":
		if honorCooldown {
			ready, err := simpleCooldownReady(tx, g, p, now)
			if err != nil || !ready {
				return err
			}
		}
		proposed = adjustedCapacity(base, int32(*p.Data.ScalingAdjustment), value(p.Data.AdjustmentType), policyMagnitude(p.Data))
	case "StepScaling":
		if metric == nil || threshold == nil || !finiteMetric(float64(*metric)) || !finiteMetric(float64(*threshold)) {
			return invalid("StepScaling requires finite MetricValue and BreachThreshold")
		}
		var matches bool
		proposed, matches = stepCapacity(p.Data, base, float64(*metric), float64(*threshold))
		if !matches {
			if alarm {
				return nil
			}
			return invalid("MetricValue does not correspond to a step adjustment")
		}
	case "TargetTrackingScaling":
		if !alarm {
			return invalid("A target tracking policy can be executed only by its managed CloudWatch alarm")
		}
		if metric == nil || !finiteMetric(float64(*metric)) || *metric < 0 {
			return invalid("A target tracking metric must be finite and nonnegative")
		}
		proposed = trackingCapacity(base, float64(*metric), float64(*p.Data.TargetTrackingConfiguration.TargetValue))
	default:
		return unsupported("The scaling policy has no runtime implementation")
	}
	if !finiteMetric(proposed) {
		return invalid("The scaling policy computed a nonfinite capacity")
	}
	if kind != "SimpleScaling" && proposed < float64(desired) {
		// Only real pending/warming membership blocks scale-in. The warmup
		// deadline starts when the reconciler admits the instance into service.
		if warming > 0 {
			return nil
		}
		if kind == "TargetTrackingScaling" {
			if trackingScaleInDisabled(p) {
				return nil
			}
			var ready bool
			proposed, ready, err = s.trackingScaleIn(service, tx, g, p, base, proposed)
			if err != nil || !ready {
				return err
			}
		}
	}
	// Do not retract already-pending scale-out when another breach calls for a
	// smaller increase. A completed warmup makes those instances the new base.
	if kind != "SimpleScaling" && proposed > float64(base) && proposed < float64(desired) {
		return nil
	}
	next := int32(min(max(proposed, float64(*g.Data.MinSize)), float64(*g.Data.MaxSize)))
	if next == desired {
		return nil
	}
	cause := fmt.Sprintf("policy %s changed desired capacity from %d to %d", p.Key.Name, desired, next)
	g.PendingInstanceWarmup = nil
	if kind != "SimpleScaling" && next > desired {
		g.PendingInstanceWarmup = new(int32(policyWarmup(p, g) / time.Second))
	}
	if alarm {
		if origin := awsctx.FromContext(ctx).ParentEventID; origin != "" {
			g.OriginEventID = origin
		}
	}
	if err = s.changeDesired(tx, g, next, cause); err != nil {
		return err
	}
	p.LastScaleAt = now
	return tx.PutPolicy(p)
}

func policyWarmup(p PolicyRecord, g GroupRecord) time.Duration {
	if p.Data.EstimatedInstanceWarmup != nil {
		return time.Duration(*p.Data.EstimatedInstanceWarmup) * time.Second
	}
	if g.Data.DefaultInstanceWarmup != nil && *g.Data.DefaultInstanceWarmup >= 0 {
		return time.Duration(*g.Data.DefaultInstanceWarmup) * time.Second
	}
	return time.Duration(*g.Data.DefaultCooldown) * time.Second
}
func simpleCooldownReady(tx Transaction, g GroupRecord, p PolicyRecord, now time.Time) (bool, error) {
	cooldown := time.Duration(*g.Data.DefaultCooldown) * time.Second
	if p.Data.Cooldown != nil {
		cooldown = time.Duration(*p.Data.Cooldown) * time.Second
	}
	baseline := p.LastScaleAt
	activities, err := tx.Activities(g.Key.Scope, g.Key.Name, false)
	if err != nil {
		return false, err
	}
	for _, a := range activities {
		if a.GroupID != g.ID || a.Kind != "launch" && a.Kind != "terminate" && a.Kind != "warm-start" && a.Kind != "warm-return" {
			continue
		}
		if a.Data.EndTime == nil {
			return false, nil
		}
		if a.Data.EndTime.After(baseline) {
			baseline = *a.Data.EndTime
		}
	}
	return baseline.IsZero() || !now.Before(baseline.Add(cooldown)), nil
}
