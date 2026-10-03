// Package servicecatalogappregistry exposes typed AppRegistry storage.
package servicecatalogappregistry

import (
	domain "stackd/internal/services/servicecatalogappregistry"
	"stackd/storage/memory"
)

type (
	Scope          = domain.Scope
	Application    = domain.Application
	AttributeGroup = domain.AttributeGroup
	Association    = domain.Association
	Configuration  = domain.Configuration
	Reader         = domain.Reader
	Transaction    = domain.Transaction
	Repository     = domain.Repository
)

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
