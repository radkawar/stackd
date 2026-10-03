// Package cloudtrail exposes service-owned CloudTrail storage contracts.
package cloudtrail

import (
	domain "stackd/internal/services/cloudtrail"
	"stackd/storage/memory"
)

type (
	Repository       = domain.Repository
	Reader           = domain.Reader
	Transaction      = domain.Transaction
	Scope            = domain.Scope
	TrailKey         = domain.TrailKey
	TrailRecord      = domain.TrailRecord
	Selection        = domain.Selection
	BasicSelector    = domain.BasicSelector
	DataResource     = domain.DataResource
	AdvancedSelector = domain.AdvancedSelector
	FieldSelector    = domain.FieldSelector
	FieldTest        = domain.FieldTest
	DeliveryStatus   = domain.DeliveryStatus
	DeliveryRecord   = domain.DeliveryRecord
	DestinationKind  = domain.DestinationKind
	DigestKeyRecord  = domain.DigestKeyRecord
	DigestStream     = domain.DigestStream
	DigestLog        = domain.DigestLog
	DigestStatus     = domain.DigestStatus
)

const (
	DestinationS3   = domain.DestinationS3
	DestinationLogs = domain.DestinationLogs
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
