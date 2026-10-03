// Package guardduty exposes the service-owned typed detector persistence boundary.
package guardduty

import (
	service "stackd/internal/services/guardduty"
	"stackd/storage/memory"
)

type (
	Scope                 = service.Scope
	Detector              = service.Detector
	Feature               = service.Feature
	AdditionalFeature     = service.AdditionalFeature
	Finding               = service.Finding
	Observation           = service.Observation
	Filter                = service.Filter
	IPList                = service.IPList
	IPListKind            = service.IPListKind
	IPRange               = service.IPRange
	PublishingDestination = service.PublishingDestination
	FindingExport         = service.FindingExport
	FindingExportDeadline = service.FindingExportDeadline
	Repository            = service.Repository
	Reader                = service.Reader
	Transaction           = service.Transaction
	MemoryRepository      = service.MemoryRepository
)

const (
	TrustedIPList = service.TrustedIPList
	ThreatIPList  = service.ThreatIPList
)

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(d) }
