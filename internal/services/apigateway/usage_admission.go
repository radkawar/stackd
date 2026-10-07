package apigateway

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"stackd/internal/services/apigatewayexec"
)

// Replenishing request budgets are process-local, as in the other service
// admission owners. Durable per-key usage is separate from burst allocation.
// AWS usage-plan throttles are best effort, not hard distributed fleet ceilings.
type usageAdmission struct {
	mu      sync.Mutex
	buckets map[usageBucketKey]usageBucket
}

type usageBucketKey struct {
	Plan                 PlanKey
	ClientKeyID          string
	APIID, Stage, Method string
	StageIncarnation     uint64
}

type usageBucket struct {
	at     time.Time
	tokens float64
}

type pendingUsageBucket struct {
	key   usageBucketKey
	value usageBucket
}

func (a *usageAdmission) available(key usageBucketKey, settings UsageThrottle, now time.Time) (usageBucket, bool) {
	bucket, exists := a.buckets[key]
	if !exists {
		bucket = usageBucket{at: now, tokens: float64(settings.Burst)}
	} else {
		if now.After(bucket.at) {
			bucket.tokens += now.Sub(bucket.at).Seconds() * settings.Rate
			bucket.at = now
		}
		bucket.tokens = math.Min(float64(settings.Burst), bucket.tokens)
	}
	if bucket.tokens < 1 {
		return bucket, false
	}
	bucket.tokens--
	return bucket, true
}

// AdmitUsage enforces live stage method limits for every REST request and the
// current plan for mapped keys. Required methods reject missing, disabled or
// unmapped keys. Quota accounting commits before customer code can run.
func (s *Service) AdmitUsage(ctx context.Context, route *apigatewayexec.Route, value string) (apigatewayexec.APIKeyIdentity, error) {
	scope := Scope{Partition: route.Partition, AccountID: route.AccountID, Region: route.Region}
	identity := apigatewayexec.APIKeyIdentity{Value: value}
	if value == "" && route.APIKeyRequired {
		return identity, failure("ForbiddenException", "Forbidden", 403)
	}
	// Serialize process-local burst reservations with the durable quota write.
	// Neither a denied request nor a failed transaction consumes a burst token.
	s.usage.mu.Lock()
	defer s.usage.mu.Unlock()
	now := s.clock.Now()
	var pending [3]pendingUsageBucket
	count := 0
	err := s.repository.Update(ctx, func(tx Transaction) error {
		reserve := func(bucketKey usageBucketKey, settings UsageThrottle) error {
			bucket, ok := s.usage.available(bucketKey, settings, now)
			if !ok {
				return failure("TooManyRequestsException", "Too Many Requests", 429)
			}
			pending[count] = pendingUsageBucket{key: bucketKey, value: bucket}
			count++
			return nil
		}
		stage, err := tx.Stage(StageKey{APIKey: APIKey{Scope: scope, ID: route.APIID}, Name: route.Stage})
		if err != nil {
			return err
		}
		method, _, _ := strings.Cut(route.RouteKey, " ")
		settings := effectiveMethodSettings(stage.MethodSettings, route.ResourcePath, method)
		stageBucket := usageBucketKey{Plan: PlanKey{Scope: scope}, APIID: route.APIID, Stage: route.Stage, Method: route.RouteKey, StageIncarnation: stage.Incarnation}
		reserveStage := func() error {
			return reserve(stageBucket, methodThrottle(settings))
		}
		if value == "" {
			return reserveStage()
		}
		key, err := tx.ClientKeyByValue(scope, value)
		if errors.Is(err, ErrNotFound) {
			if route.APIKeyRequired {
				return failure("ForbiddenException", "Forbidden", 403)
			}
			return reserveStage()
		}
		if err != nil {
			return err
		}
		identity.ID = key.Key.ID
		if !key.Enabled && route.APIKeyRequired {
			return failure("ForbiddenException", "Forbidden", 403)
		}
		plans, err := tx.UsagePlansForKey(key.Key)
		if err != nil {
			return err
		}
		for _, plan := range plans {
			for _, stage := range plan.Stages {
				if stage.Key.ID != route.APIID || stage.Key.Name != route.Stage {
					continue
				}
				bucketKey := usageBucketKey{Plan: plan.Key, ClientKeyID: key.Key.ID}
				if plan.Throttle != nil {
					if err := reserve(bucketKey, *plan.Throttle); err != nil {
						return err
					}
				}
				if throttle, ok := stage.Throttle[route.ResourcePath+"/"+method]; ok {
					bucketKey.APIID, bucketKey.Stage, bucketKey.Method = route.APIID, route.Stage, route.RouteKey
					if err := reserve(bucketKey, throttle); err != nil {
						return err
					}
				}
				if plan.Quota != nil {
					start, end := usagePeriod(now, plan.Quota.Period)
					used, err := tx.UsageCount(plan.Key, key.Key.ID, start, end)
					if err != nil {
						return err
					}
					membership, err := tx.UsagePlanMembership(plan.Key, key.Key.ID)
					if err != nil {
						return err
					}
					if !membership.Created.Before(start) && membership.Created.Before(end) {
						used += int64(plan.Quota.Offset)
					}
					if used >= int64(plan.Quota.Limit) {
						return failure("LimitExceededException", "Limit Exceeded", 429)
					}
					day, _ := usagePeriod(now, UsageDay)
					if err := tx.IncrementUsage(plan.Key, key.Key.ID, day); err != nil {
						return err
					}
				}
				return reserveStage()
			}
		}
		if route.APIKeyRequired {
			return failure("ForbiddenException", "Forbidden", 403)
		}
		return reserveStage()
	})
	if err != nil {
		return apigatewayexec.APIKeyIdentity{}, err
	}
	if count != 0 && s.usage.buckets == nil {
		s.usage.buckets = make(map[usageBucketKey]usageBucket)
	}
	for _, bucket := range pending[:count] {
		s.usage.buckets[bucket.key] = bucket.value
	}
	return identity, nil
}

func usagePeriod(now time.Time, period UsagePeriod) (time.Time, time.Time) {
	now = now.UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	switch period {
	case UsageWeek:
		// TODO: Comeback calibrate the weekly reset and initial offset boundary
		// against native AWS; current periods use UTC ISO calendar weeks.
		start := day.AddDate(0, 0, -(int(day.Weekday())+6)%7)
		return start, start.AddDate(0, 0, 7)
	case UsageMonth:
		start := time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 1, 0)
	default:
		return day, day.AddDate(0, 0, 1)
	}
}
