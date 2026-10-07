// Package eventbridge exposes service-owned EventBridge storage contracts.
package eventbridge

import (
	domain "stackd/internal/services/eventbridge"
	"stackd/storage/memory"
)

type (
	Repository           = domain.Repository
	Reader               = domain.Reader
	Transaction          = domain.Transaction
	Scope                = domain.Scope
	BusKey               = domain.BusKey
	RuleKey              = domain.RuleKey
	BusRecord            = domain.BusRecord
	PolicyStatementOwner = domain.PolicyStatementOwner
	RuleRecord           = domain.RuleRecord
	TargetRecord         = domain.TargetRecord
	EventRecord          = domain.EventRecord
	DeliveryRecord       = domain.DeliveryRecord
	ArchiveKey           = domain.ArchiveKey
	ArchivePayload       = domain.ArchivePayload
	ArchiveRecord        = domain.ArchiveRecord
	ArchiveCursor        = domain.ArchiveCursor
	ArchiveEntry         = domain.ArchiveEntry
	ReplayKey            = domain.ReplayKey
	ReplayRecord         = domain.ReplayRecord
	MetricPublicationKey = domain.MetricPublicationKey
	MetricSample         = domain.MetricSample
	MetricReader         = domain.MetricReader
	MetricWriter         = domain.MetricWriter
	ConnectionKey        = domain.ConnectionKey
	ConnectionRecord     = domain.ConnectionRecord
	ConnectionParameter  = domain.ConnectionParameter
	ConnectionReader     = domain.ConnectionReader
	ConnectionWriter     = domain.ConnectionWriter
	APIDestinationKey    = domain.APIDestinationKey
	APIDestinationRecord = domain.APIDestinationRecord
	APIDestinationReader = domain.APIDestinationReader
	APIDestinationWriter = domain.APIDestinationWriter
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
