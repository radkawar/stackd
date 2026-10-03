// Package ecs exposes service-owned ECS storage contracts.
package ecs

import (
	domain "stackd/internal/services/ecs"
	"stackd/storage/memory"
)

type (
	Repository            = domain.Repository
	Reader                = domain.Reader
	Transaction           = domain.Transaction
	Scope                 = domain.Scope
	ClusterKey            = domain.ClusterKey
	FamilyKey             = domain.FamilyKey
	TaskDefinitionKey     = domain.TaskDefinitionKey
	TagKey                = domain.TagKey
	ClusterRecord         = domain.ClusterRecord
	TaskDefinitionRecord  = domain.TaskDefinitionRecord
	TagRecord             = domain.TagRecord
	ClusterQuery          = domain.ClusterQuery
	TaskDefinitionQuery   = domain.TaskDefinitionQuery
	TaskKey               = domain.TaskKey
	TaskRecord            = domain.TaskRecord
	TaskQuery             = domain.TaskQuery
	TaskRunKey            = domain.TaskRunKey
	TaskRunRecord         = domain.TaskRunRecord
	ServiceKey            = domain.ServiceKey
	ServiceRecord         = domain.ServiceRecord
	ServiceDeployment     = domain.ServiceDeployment
	ServiceQuery          = domain.ServiceQuery
	ServiceRevisionKey    = domain.ServiceRevisionKey
	ServiceRevisionRecord = domain.ServiceRevisionRecord
	MetricPublicationKey  = domain.MetricPublicationKey
	MetricSample          = domain.MetricSample
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
