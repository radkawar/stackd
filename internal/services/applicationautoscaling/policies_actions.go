package applicationautoscaling

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudwatch"
)

// ApplyAlarm accepts the retained CloudWatch action, not an unsigned public
// ExecutePolicy API. Resource commands execute under the real service-linked
// role and remain subject to the resource owner's authorization and lifecycle.
func (s *Service) ApplyAlarm(ctx context.Context, policyARN string, input cloudwatch.ScalingAlarmSignal) *awswire.Error {
	metadata := awsctx.FromContext(ctx)
	scope := scopeFor(ctx)
	source, err := arn.Parse(metadata.ServicePrincipal.SourceARN)
	if metadata.ServicePrincipal.Name != "cloudwatch.amazonaws.com" || err != nil || source.Service != "cloudwatch" || source.Partition != scope.Partition || source.AccountID != scope.AccountID || source.Region != scope.Region || !strings.HasPrefix(source.Resource, "alarm:") {
		return &awswire.Error{Code: "AccessDeniedException", Message: "A scoped CloudWatch alarm delivery is required.", StatusCode: 403}
	}
	key, err := alarmPolicyKey(scope, policyARN)
	if err != nil {
		return wireError(err)
	}
	signal, err := decodeAlarmSignal(input, s.clock.Now())
	if err != nil {
		return wireError(err)
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		// Policy ARNs carry the target identity, not its scalable dimension.
		// Resolve the exact retained ARN so read/write policies with the same
		// name cannot accidentally execute each other's capacity change.
		policies, err := tx.Policies(PolicyQuery{Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Names: []string{key.Name}})
		if err != nil {
			return err
		}
		var policy PolicyRecord
		found := false
		for _, candidate := range policies {
			expected := value(candidate.Data.PolicyARN)
			if candidate.ManagedActionID != "" {
				expected += ":createdBy/" + candidate.ManagedActionID
			}
			if policyARN == expected {
				policy, found = candidate, true
				break
			}
		}
		if !found {
			return failure("ObjectNotFoundException", "Scaling policy not found")
		}
		key = policy.Key
		if handled, err := s.refreshDynamoDBAlarms(tx.Context(), tx, &policy, strings.TrimPrefix(source.Resource, "alarm:"), signal.threshold); handled {
			return err
		}
		target, err := tx.Target(key.TargetKey)
		if errors.Is(err, ErrNotFound) {
			return failure("ObjectNotFoundException", "Scalable target not found")
		}
		if err != nil {
			return err
		}
		service, err := s.identity.Context(tx.Context(), key.TargetKey, "AutoScaling-UpdateDesiredCapacity")
		if err != nil {
			return err
		}
		capacity, err := s.resources.Capacity(service, key.TargetKey)
		if errors.Is(err, ErrNotFound) {
			return resourceMissing(service, s, tx, target)
		}
		if err != nil {
			return err
		}
		cause := fmt.Sprintf("monitor alarm %s in state ALARM triggered policy %s", strings.TrimPrefix(source.Resource, "alarm:"), key.Name)
		var proposed float64
		switch value(policy.Data.PolicyType) {
		case "StepScaling":
			var matches bool
			proposed, matches, err = stepCapacity(policy.Data.StepScalingPolicyConfiguration, capacity.Running, signal)
			if err != nil || !matches {
				return err
			}
		case "TargetTrackingScaling":
			metric := trackingMetricValue(policy, capacity.Running, aggregateSignal(signal.values, "Average"))
			if math.IsInf(metric, 0) {
				return invalid("The aggregated metric is not finite")
			}
			config := policy.Data.TargetTrackingScalingPolicyConfiguration
			if signal.below && metric >= trackingLowTarget(policy) || !signal.below && metric <= float64(*config.TargetValue) {
				return nil
			}
			proposed = trackingCapacity(config, capacity.Running, metric)
		default:
			return unsupported("The scaling policy type has no runtime implementation")
		}
		scaleOut := proposed > float64(capacity.Running)
		if !scaleOut && proposed >= float64(capacity.Running) {
			return s.recordNotScaled(tx, key.TargetKey, cause, api.NotScaledReason{Code: new(api.XmlString("AlreadyAtDesiredCapacity")), CurrentCapacity: new(api.ResourceCapacity(capacity.Desired))})
		}
		if !scaleOut && capacity.DeploymentInProgress {
			return s.recordNotScaled(tx, key.TargetKey, cause, api.NotScaledReason{Code: new(api.XmlString("TargetServicePutResourceAsUnscalable"))})
		}
		if state := target.Data.SuspendedState; state != nil {
			if scaleOut && state.DynamicScalingOutSuspended != nil && bool(*state.DynamicScalingOutSuspended) {
				return nil
			}
			if !scaleOut && state.DynamicScalingInSuspended != nil && bool(*state.DynamicScalingInSuspended) {
				return nil
			}
		}
		policies, err = tx.Policies(PolicyQuery{Scope: key.Scope, Namespace: key.Namespace, ResourceID: key.ResourceID, Dimension: key.Dimension})
		if err != nil {
			return err
		}
		if !scaleOut && policy.Data.TargetTrackingScalingPolicyConfiguration != nil {
			if scaleInDisabled(policy) {
				return nil
			}
			var ready bool
			proposed, ready, err = s.trackingScaleIn(service, policies, policy, capacity, proposed)
			if err != nil || !ready {
				return err
			}
		}
		now := s.clock.Now()
		scaleFrom := capacity.Running
		if !policy.LastScaleAt.IsZero() && now.Before(policy.LastScaleAt.Add(policyCooldown(policy, scaleOut))) {
			if scaleOut && policy.LastScaleTo > policy.LastScaleFrom {
				// Keep the entire active cooldown's capacity credit, including
				// earlier escalations, rather than only the most recent increment.
				proposed -= float64(policy.LastScaleTo - policy.LastScaleFrom)
				scaleFrom = policy.LastScaleFrom
			} else if !scaleOut && policy.LastScaleTo < policy.LastScaleFrom {
				return nil
			}
		}
		desired := boundedCapacity(target, proposed)
		if scaleOut && desired <= capacity.Desired || !scaleOut && desired >= capacity.Desired {
			reason := api.NotScaledReason{Code: new(api.XmlString("AlreadyAtDesiredCapacity")), CurrentCapacity: new(api.ResourceCapacity(capacity.Desired))}
			if scaleOut && capacity.Desired >= int32(*target.Data.MaxCapacity) {
				reason = api.NotScaledReason{Code: new(api.XmlString("AlreadyAtMaxCapacity")), MaxCapacity: new(*target.Data.MaxCapacity)}
			} else if !scaleOut && capacity.Desired <= int32(*target.Data.MinCapacity) {
				reason = api.NotScaledReason{Code: new(api.XmlString("AlreadyAtMinCapacity")), MinCapacity: new(*target.Data.MinCapacity)}
			}
			return s.recordNotScaled(tx, key.TargetKey, cause, reason)
		}
		if scaleOut {
			// A scale-out interrupts active scale-in cooldowns on this target.
			for _, previous := range policies {
				if previous.LastScaleTo >= previous.LastScaleFrom || previous.LastScaleAt.IsZero() {
					continue
				}
				previous.LastScaleAt = time.Time{}
				previous.LastScaleFrom, previous.LastScaleTo = 0, 0
				if previous.Key == policy.Key {
					policy = previous
					continue
				}
				if err := tx.PutPolicy(previous); err != nil {
					return err
				}
			}
		}
		activity := s.capacityActivity(key.TargetKey, scaleFrom, desired, cause)
		return s.queueCapacity(service, tx, activity, &policy)
	})
	if err == nil {
		s.jobs.Wake()
	}
	return wireError(err)
}

func alarmPolicyKey(scope Scope, resource string) (PolicyKey, error) {
	parsed, err := arn.Parse(resource)
	if err != nil || parsed.Service != "autoscaling" || parsed.Partition != scope.Partition || parsed.AccountID != scope.AccountID || parsed.Region != scope.Region {
		return PolicyKey{}, failure("ObjectNotFoundException", "Scaling policy not found")
	}
	_, target, ok := strings.Cut(parsed.Resource, ":resource/")
	if !ok {
		return PolicyKey{}, unsupported("Only Application Auto Scaling policy actions are supported")
	}
	namespace, target, ok := strings.Cut(target, "/")
	if !ok || namespace != "ecs" && namespace != "dynamodb" {
		return PolicyKey{}, unsupported("The scaling policy namespace has no resource integration")
	}
	resourceID, name, ok := strings.Cut(target, ":policyName/")
	if !ok || !validResource(namespace, resourceID, "") || name == "" {
		return PolicyKey{}, failure("ObjectNotFoundException", "Scaling policy not found")
	}
	if suffix := strings.LastIndex(name, ":createdBy/"); suffix >= 0 {
		name = name[:suffix]
	}
	return PolicyKey{TargetKey: TargetKey{Scope: scope, Namespace: namespace, ResourceID: resourceID}, Name: name}, nil
}
