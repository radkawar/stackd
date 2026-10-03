// Package logs exposes service-owned CloudWatch Logs storage contracts.
package logs

import (
	domain "stackd/internal/services/logs"
	"stackd/storage/memory"
)

type (
	Repository           = domain.Repository
	Reader               = domain.Reader
	Transaction          = domain.Transaction
	Scope                = domain.Scope
	GroupKey             = domain.GroupKey
	GroupRecord          = domain.GroupRecord
	GroupQuery           = domain.GroupQuery
	StreamKey            = domain.StreamKey
	StreamRecord         = domain.StreamRecord
	StreamQuery          = domain.StreamQuery
	EventCursor          = domain.EventCursor
	EventRecord          = domain.EventRecord
	EventQuery           = domain.EventQuery
	PolicyScope          = domain.PolicyScope
	PolicyKey            = domain.PolicyKey
	PolicyRecord         = domain.PolicyRecord
	PolicyQuery          = domain.PolicyQuery
	DestinationKey       = domain.DestinationKey
	DestinationRecord    = domain.DestinationRecord
	DestinationQuery     = domain.DestinationQuery
	SubscriptionKey      = domain.SubscriptionKey
	SubscriptionRecord   = domain.SubscriptionRecord
	SubscriptionQuery    = domain.SubscriptionQuery
	SubscriptionDelivery = domain.SubscriptionDelivery
	MetricFilterKey      = domain.MetricFilterKey
	MetricFilterRecord   = domain.MetricFilterRecord
	MetricFilterQuery    = domain.MetricFilterQuery
)

const (
	PolicyScopeAccount  = domain.PolicyScopeAccount
	PolicyScopeResource = domain.PolicyScopeResource
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
