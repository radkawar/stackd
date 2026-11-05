// Package s3tables exposes typed table catalog persistence and private warehouse bytes.
package s3tables

import (
	service "stackd/internal/services/s3tables"
	"stackd/storage/memory"
)

type (
	Scope            = service.Scope
	Bucket           = service.Bucket
	Namespace        = service.Namespace
	Table            = service.Table
	Column           = service.Column
	Reader           = service.Reader
	Transaction      = service.Transaction
	Repository       = service.Repository
	MemoryRepository = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(d) }
