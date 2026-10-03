// Package codebuild exposes service-owned CodeBuild storage contracts.
package codebuild

import (
	domain "stackd/internal/services/codebuild"
	"stackd/storage/memory"
)

type (
	Repository       = domain.Repository
	Reader           = domain.Reader
	Transaction      = domain.Transaction
	Scope            = domain.Scope
	ProjectKey       = domain.ProjectKey
	BuildKey         = domain.BuildKey
	FleetKey         = domain.FleetKey
	CredentialKey    = domain.CredentialKey
	ProjectRecord    = domain.ProjectRecord
	BuildRecord      = domain.BuildRecord
	PipelineInput    = domain.PipelineInput
	PipelineOutput   = domain.PipelineOutput
	FleetRecord      = domain.FleetRecord
	CredentialRecord = domain.CredentialRecord
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
