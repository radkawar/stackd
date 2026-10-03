package apigateway

import "time"

type PlanKey struct {
	Scope
	ID string
}

type UsageThrottle struct {
	Burst int32
	Rate  float64
}

type UsagePeriod string

const (
	UsageDay   UsagePeriod = "DAY"
	UsageWeek  UsagePeriod = "WEEK"
	UsageMonth UsagePeriod = "MONTH"
)

type UsageQuota struct {
	Limit, Offset int32
	Period        UsagePeriod
}

type UsagePlanStage struct {
	Key      StageKey
	Throttle map[string]UsageThrottle
}

type UsagePlanRecord struct {
	Key         PlanKey
	Name        string
	Description *string
	Throttle    *UsageThrottle
	Quota       *UsageQuota
	Stages      []UsagePlanStage
	Tags        map[string]string
}

// UsagePlanMembership retains when this key joined the plan. Key names and
// values remain owned by ClientKeyRecord, not copied into each membership.
type UsagePlanMembership struct {
	Plan        PlanKey
	ClientKeyID string
	Created     time.Time
}
