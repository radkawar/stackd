// Package configservice exposes the service-owned typed AWS Config repository.
package configservice

import (
	domain "stackd/internal/services/configservice"
	"stackd/storage/memory"
)

type (
	CloudFormationOwnership  = domain.CloudFormationOwnership
	Repository               = domain.Repository
	Reader                   = domain.Reader
	Transaction              = domain.Transaction
	Scope                    = domain.Scope
	Recorder                 = domain.Recorder
	Channel                  = domain.Channel
	Item                     = domain.Item
	Relationship             = domain.Relationship
	Delivery                 = domain.Delivery
	Rule                     = domain.Rule
	Evaluation               = domain.Evaluation
	EvaluationRun            = domain.EvaluationRun
	Aggregator               = domain.Aggregator
	AggregationSource        = domain.AggregationSource
	AggregationAuthorization = domain.AggregationAuthorization
)

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
