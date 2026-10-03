// Package appsync exposes the service-owned typed AppSync repository.
package appsync

import (
	domain "stackd/internal/services/appsync"
	"stackd/storage/memory"
)

type (
	Repository       = domain.Repository
	Reader           = domain.Reader
	Transaction      = domain.Transaction
	Key              = domain.Key
	APIRecord        = domain.APIRecord
	DataSourceRecord = domain.DataSourceRecord
	ResolverRecord   = domain.ResolverRecord
	FunctionRecord   = domain.FunctionRecord
	APIKeyRecord     = domain.APIKeyRecord
)

var (
	ErrNotFound = domain.ErrNotFound
	ErrConflict = domain.ErrConflict
)

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
func CheckFunctionReferences(r Reader, p FunctionRecord) error {
	return domain.CheckFunctionReferences(r, p)
}
func CheckResolverReferences(r Reader, p ResolverRecord) error {
	return domain.CheckResolverReferences(r, p)
}
func CheckDeleteDataSource(r Reader, k Key, name string) error {
	return domain.CheckDeleteDataSource(r, k, name)
}
func CheckDeleteFunction(r Reader, k Key, id string) error {
	return domain.CheckDeleteFunction(r, k, id)
}
