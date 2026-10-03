// Package cloudcontrol exposes the typed asynchronous request repository.
package cloudcontrol

import (
	"stackd/internal/services/cloudcontrol"
	"stackd/storage/memory"
)

type Scope = cloudcontrol.Scope
type RequestRecord = cloudcontrol.RequestRecord
type Reader = cloudcontrol.Reader
type Transaction = cloudcontrol.Transaction
type Repository = cloudcontrol.Repository

var ErrNotFound = cloudcontrol.ErrNotFound

func NewMemory(domain *memory.Domain) Repository { return cloudcontrol.NewMemoryRepository(domain) }
