package xray

import (
	"time"

	api "stackd/internal/awsapi/xray"
)

// SamplingRuleKey identifies a regional rule independently of its match criteria.
type SamplingRuleKey struct {
	Scope
	Name string
}

func (k SamplingRuleKey) ARN() string {
	return "arn:" + k.Partition + ":xray:" + k.Region + ":" + k.AccountID + ":sampling-rule/" + k.Name
}

// SamplingRuleRecord owns validated rule configuration and its resource tags.
// Version is the wire format version, not mutable resource state.
type SamplingRuleRecord struct {
	Key           SamplingRuleKey
	Priority      int32
	FixedRate     float64
	ReservoirSize int32
	Host          string
	HTTPMethod    string
	ResourceARN   string
	ServiceName   string
	ServiceType   string
	URLPath       string
	Attributes    map[string]string
	RateBoost     *api.SamplingRateBoost
	Tags          map[string]string
	CFNOwner      string
	Created       time.Time
	Modified      time.Time
}

type SamplingClientKey struct {
	Rule SamplingRuleKey
	ID   string
}

// SamplingClientRecord keeps outstanding quotas until the SDK refreshes or the
// lease expires. A new client cannot spend quota already assigned elsewhere.
type SamplingClientRecord struct {
	Key          SamplingClientKey
	FirstSeen    time.Time
	LastSeen     time.Time
	Quota        int32
	QuotaExpires time.Time
}

// SamplingStatisticKey separates client reports within a rule's reporting window.
type SamplingStatisticKey struct {
	Rule     SamplingRuleKey
	ClientID string
	Window   time.Time
}

type SamplingStatisticRecord struct {
	Key          SamplingStatisticKey
	Timestamp    time.Time
	Received     time.Time
	RequestCount int64
	SampledCount int64
	BorrowCount  int64
}

// SamplingBoostStatisticKey isolates a service's report within a sampling window.
type SamplingBoostStatisticKey struct {
	Rule        SamplingRuleKey
	ServiceName string
	Window      time.Time
}

type SamplingBoostStatisticRecord struct {
	Key                 SamplingBoostStatisticKey
	Timestamp           time.Time
	Received            time.Time
	TotalCount          int64
	AnomalyCount        int64
	SampledAnomalyCount int64
}

// SamplingBoostRecord retains cooldown history after the active boost expires.
// Its lifetime is bounded by the owning sampling rule.
type SamplingBoostRecord struct {
	Key       SamplingRuleKey
	Rate      float64
	Expires   time.Time
	Triggered time.Time
}
