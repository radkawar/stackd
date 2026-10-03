// Package cloudformation exposes the service-owned deployment repository.
package cloudformation

import (
	domain "stackd/internal/services/cloudformation"
	"stackd/storage/memory"
)

type (
	Repository      = domain.Repository
	Reader          = domain.Reader
	Transaction     = domain.Transaction
	Scope           = domain.Scope
	Properties      = domain.Properties
	StackRecord     = domain.StackRecord
	ResourceRecord  = domain.ResourceRecord
	EventRecord     = domain.EventRecord
	StepRecord      = domain.StepRecord
	OperationRecord = domain.OperationRecord
	ChangeRecord    = domain.ChangeRecord
	ChangeSetRecord = domain.ChangeSetRecord
	ExportRecord    = domain.ExportRecord
	OutputValue     = domain.OutputValue
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
