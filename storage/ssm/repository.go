// Package ssm exposes service-owned Parameter Store storage contracts.
package ssm

import (
	domain "stackd/internal/services/ssm"
	"stackd/storage/memory"
)

type (
	Repository      = domain.Repository
	Reader          = domain.Reader
	Transaction     = domain.Transaction
	Scope           = domain.Scope
	ParameterKey    = domain.ParameterKey
	VersionKey      = domain.VersionKey
	ParameterRecord = domain.ParameterRecord
	VersionRecord   = domain.VersionRecord
	ParameterPolicy = domain.ParameterPolicy
	ResourcePolicy  = domain.ResourcePolicy
	SettingRecord   = domain.SettingRecord
	ValidationJob   = domain.ValidationJob
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
