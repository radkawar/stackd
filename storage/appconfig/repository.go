// Package appconfig exposes the service-owned typed AppConfig repository.
// Resource catalogs, immutable deployment snapshots and polling sessions have
// independent lifetimes. Readers return detached mutable values; related owners
// join writes through Reader.Context. Attempt is an explicit recoverable command
// savepoint, whereas a failed nested Update aborts its enclosing transaction.
package appconfig

import (
	domain "stackd/internal/services/appconfig"
	"stackd/storage/memory"
)

type (
	Repository              = domain.Repository
	Reader                  = domain.Reader
	Transaction             = domain.Transaction
	Scope                   = domain.Scope
	CloudFormationOwnership = domain.CloudFormationOwnership
	Application             = domain.Application
	Environment             = domain.Environment
	Monitor                 = domain.Monitor
	Profile                 = domain.Profile
	Validator               = domain.Validator
	HostedVersion           = domain.HostedVersion
	Strategy                = domain.Strategy
	Deployment              = domain.Deployment
	DeploymentEvent         = domain.DeploymentEvent
	ActionInvocation        = domain.ActionInvocation
	AppliedExtension        = domain.AppliedExtension
	Session                 = domain.Session
	Extension               = domain.Extension
	ExtensionAction         = domain.ExtensionAction
	ExtensionParameter      = domain.ExtensionParameter
	Association             = domain.Association
	Settings                = domain.Settings
)

// NewMemory enlists AppConfig in d. A nil domain creates an independent owner.
func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
