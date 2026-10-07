// Package sns exposes service-owned SNS storage contracts.
package sns

import (
	"stackd/internal/awsctx"
	domain "stackd/internal/services/sns"
	"stackd/storage/memory"
)

type (
	Repository             = domain.Repository
	Reader                 = domain.Reader
	Transaction            = domain.Transaction
	Scope                  = domain.Scope
	TopicKey               = domain.TopicKey
	SubscriptionKey        = domain.SubscriptionKey
	MessageKey             = domain.MessageKey
	TopicRecord            = domain.TopicRecord
	TopicCreationOwner     = domain.TopicCreationOwner
	PolicyOwnership        = domain.PolicyOwnership
	FeedbackConfig         = domain.FeedbackConfig
	ArchiveConfig          = domain.ArchiveConfig
	ArchiveEntry           = domain.ArchiveEntry
	ReplayRecord           = domain.ReplayRecord
	TopicQuery             = domain.TopicQuery
	SubscriptionRecord     = domain.SubscriptionRecord
	ConfirmationRecord     = domain.ConfirmationRecord
	TopicSubscriptionQuery = domain.TopicSubscriptionQuery
	OwnerSubscriptionQuery = domain.OwnerSubscriptionQuery
	MessageRecord          = domain.MessageRecord
	CallerMetadata         = awsctx.Metadata
	DeliveryRecord         = domain.DeliveryRecord
	DeduplicationKey       = domain.DeduplicationKey
	DeduplicationRecord    = domain.DeduplicationRecord
	MetricPublicationKey   = domain.MetricPublicationKey
	MetricSample           = domain.MetricSample
	SigningKeyRecord       = domain.SigningKeyRecord
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
