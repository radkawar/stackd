// Package xray exposes service-owned X-Ray storage contracts.
package xray

import (
	domain "stackd/internal/services/xray"
	"stackd/storage/memory"
)

type (
	Repository                   = domain.Repository
	Reader                       = domain.Reader
	Transaction                  = domain.Transaction
	Scope                        = domain.Scope
	TraceKey                     = domain.TraceKey
	SegmentKey                   = domain.SegmentKey
	SegmentRecord                = domain.SegmentRecord
	PolicyKey                    = domain.PolicyKey
	PolicyRecord                 = domain.PolicyRecord
	SamplingRuleKey              = domain.SamplingRuleKey
	SamplingRuleRecord           = domain.SamplingRuleRecord
	SamplingClientKey            = domain.SamplingClientKey
	SamplingClientRecord         = domain.SamplingClientRecord
	SamplingStatisticKey         = domain.SamplingStatisticKey
	SamplingStatisticRecord      = domain.SamplingStatisticRecord
	SamplingBoostStatisticKey    = domain.SamplingBoostStatisticKey
	SamplingBoostStatisticRecord = domain.SamplingBoostStatisticRecord
	SamplingBoostRecord          = domain.SamplingBoostRecord
	TraceRecord                  = domain.TraceRecord
	TraceSelection               = domain.TraceSelection
	TraceSelectionKind           = domain.TraceSelectionKind
	TraceData                    = domain.TraceData
	GroupKey                     = domain.GroupKey
	GroupRecord                  = domain.GroupRecord
	GroupMembership              = domain.GroupMembership
	GroupMetricKey               = domain.GroupMetricKey
	GroupMetricRecord            = domain.GroupMetricRecord
)

const (
	TraceStartTime      = domain.TraceStartTime
	TraceEventTime      = domain.TraceEventTime
	TraceServiceTime    = domain.TraceServiceTime
	TraceCompletionTime = domain.TraceCompletionTime
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
