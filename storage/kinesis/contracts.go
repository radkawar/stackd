// Package kinesis exposes service-owned control metadata storage. Record bytes belong to the external log runtime.
package kinesis

import (
	domain "stackd/internal/services/kinesis"
	"stackd/storage/memory"
)

type (
	Repository           = domain.Repository
	Reader               = domain.Reader
	Transaction          = domain.Transaction
	Scope                = domain.Scope
	StreamKey            = domain.StreamKey
	ResourceOwner        = domain.ResourceOwner
	StreamRecord         = domain.StreamRecord
	StreamUpdate         = domain.StreamUpdate
	StreamQuery          = domain.StreamQuery
	ShardKey             = domain.ShardKey
	ShardState           = domain.ShardState
	ShardRecord          = domain.ShardRecord
	ConsumerKey          = domain.ConsumerKey
	ConsumerRecord       = domain.ConsumerRecord
	ResourceKey          = domain.ResourceKey
	TagRecord            = domain.TagRecord
	PolicyRecord         = domain.PolicyRecord
	AccountRecord        = domain.AccountRecord
	MetricPublicationKey = domain.MetricPublicationKey
	MetricSample         = domain.MetricSample
	EncryptionUpdate     = domain.EncryptionUpdate
)

const (
	ShardOpening = domain.ShardOpening
	ShardOpen    = domain.ShardOpen
	ShardClosed  = domain.ShardClosed
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
