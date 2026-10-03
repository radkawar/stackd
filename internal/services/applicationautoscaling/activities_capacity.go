package applicationautoscaling

import (
	"context"
	"errors"
	"fmt"
	"time"

	api "stackd/internal/awsapi/applicationautoscaling"
)

// ObserveCapacity joins the resource lifecycle transaction. Actual capacity
// completes accepted work; an external ECS desired-count change overrides it. Policy
// cooldowns follow their own completed activity, not merely API acceptance.
func (s *Service) ObserveCapacity(ctx context.Context, key TargetKey, desired, running int32) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		activities, err := tx.PendingActivities(key)
		if err != nil {
			return err
		}
		refreshDynamoDB := false
		for _, activity := range activities {
			if *activity.Data.StatusCode == api.ScalingActivityStatusCodePending {
				continue
			}
			// DynamoDB describes actual provisioned capacity, not a separate
			// desired intent. An older observation during UpdateTable cannot
			// establish an override; only the observed requested capacity
			// completes the activity.
			if key.Namespace == "dynamodb" && desired != activity.To {
				continue
			}
			// TODO: Comeback establish native Unfulfilled transitions. A
			// capacity-starved ECS service remained InProgress after 30 minutes;
			// the status enum alone does not justify inventing a timeout.
			fulfilled := activity.To > activity.From && running >= activity.To || activity.To <= activity.From && running <= activity.To
			if desired == activity.To && !fulfilled {
				continue
			}
			activity.Data.EndTime = new(s.clock.Now().UTC().Truncate(time.Millisecond))
			if desired == activity.To {
				activity.Data.StatusCode = new(api.ScalingActivityStatusCodeSuccessful)
				activity.Data.StatusMessage = new(api.XmlString(fmt.Sprintf("Successfully set %s to %d. Change successfully fulfilled by %s.", capacityName(key), activity.To, key.Namespace)))
				refreshDynamoDB = refreshDynamoDB || key.Namespace == "dynamodb"
			} else {
				activity.Data.StatusCode = new(api.ScalingActivityStatusCodeOverridden)
				activity.Data.StatusMessage = new(api.XmlString(fmt.Sprintf("Successfully set %s to %d. Found it was later changed to %d.", capacityName(key), activity.To, desired)))
			}
			if err := s.finishActivity(tx, activity); err != nil {
				return err
			}
		}
		if refreshDynamoDB {
			return s.refreshDynamoDBTargetAlarms(tx, key, running)
		}
		return nil
	})
}

func (s *Service) finishActivity(tx Transaction, activity ActivityRecord) error {
	if err := tx.PutActivity(activity); err != nil {
		return err
	}
	if activity.PolicyName == "" {
		return nil
	}
	policy, err := tx.Policy(PolicyKey{TargetKey: activityTarget(activity), Name: activity.PolicyName})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if policy.PendingActivityID != activity.Key.ID {
		return nil
	}
	if *activity.Data.StatusCode == api.ScalingActivityStatusCodeSuccessful {
		policy.LastScaleAt = *activity.Data.EndTime
		policy.LastScaleFrom, policy.LastScaleTo = activity.From, activity.To
	}
	policy.PendingActivityID = ""
	return tx.PutPolicy(policy)
}
