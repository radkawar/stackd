// Package acm exposes typed certificate storage for replaceable backends.
package acm

import (
	service "stackd/internal/services/acm"
	"stackd/storage/memory"
)

type Scope = service.Scope
type CertificateRecord = service.CertificateRecord
type CertificateState = service.CertificateState
type Validation = service.Validation
type ValidationToken = service.ValidationToken
type Authority = service.Authority
type Receipt = service.Receipt
type Reader = service.Reader
type Transaction = service.Transaction
type Repository = service.Repository

var ErrNotFound = service.ErrNotFound

func NewMemory(domain *memory.Domain) Repository { return service.NewMemoryRepository(domain) }
