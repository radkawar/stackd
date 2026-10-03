// Package signer exposes typed signing authority persistence.
package signer

import (
	service "stackd/internal/services/signer"
	"stackd/storage/memory"
)

type (
	Scope            = service.Scope
	Authority        = service.Authority
	Profile          = service.Profile
	Job              = service.Job
	Reader           = service.Reader
	Transaction      = service.Transaction
	Repository       = service.Repository
	MemoryRepository = service.MemoryRepository
)

var ErrNotFound = service.ErrNotFound

func NewMemory(d *memory.Domain) *MemoryRepository { return service.NewMemoryRepository(d) }
