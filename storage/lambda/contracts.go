// Package lambda exposes service-owned Lambda storage contracts.
package lambda

import (
	"stackd/internal/scheduler"
	domain "stackd/internal/services/lambda"
	"stackd/storage/memory"
)

type (
	Repository                   = domain.Repository
	Reader                       = domain.Reader
	Transaction                  = domain.Transaction
	Scope                        = domain.Scope
	FunctionKey                  = domain.FunctionKey
	FunctionRecord               = domain.FunctionRecord
	FunctionOwner                = domain.FunctionOwner
	FunctionNetworkConfiguration = domain.FunctionNetworkConfiguration
	AdditionalOwner              = domain.AdditionalOwner
	FunctionReference            = domain.FunctionReference
	FunctionVersionKey           = domain.FunctionVersionKey
	VersionOwner                 = domain.VersionOwner
	AliasOwner                   = domain.AliasOwner
	AliasRecord                  = domain.AliasRecord
	VersionReader                = domain.VersionReader
	VersionWriter                = domain.VersionWriter
	AliasReader                  = domain.AliasReader
	AliasWriter                  = domain.AliasWriter
	CodeArchiveKey               = domain.CodeArchiveKey
	CodeArchive                  = domain.CodeArchive
	CodeSigningKey               = domain.CodeSigningKey
	CodeReader                   = domain.CodeReader
	CodeWriter                   = domain.CodeWriter
	LayerKey                     = domain.LayerKey
	LayerVersionKey              = domain.LayerVersionKey
	LayerAttachment              = domain.LayerAttachment
	LayerVersionRecord           = domain.LayerVersionRecord
	LayerVersionOwner            = domain.LayerVersionOwner
	LayerPermissionKey           = domain.LayerPermissionKey
	LayerPermissionOwner         = domain.LayerPermissionOwner
	LayerPolicy                  = domain.LayerPolicy
	LayerReader                  = domain.LayerReader
	LayerWriter                  = domain.LayerWriter
	S3ObjectReference            = domain.S3ObjectReference
	FunctionPolicy               = domain.FunctionPolicy
	FunctionPolicyOwner          = domain.FunctionPolicyOwner
	FunctionPolicyDeployment     = domain.FunctionPolicyDeployment
	PolicyReader                 = domain.PolicyReader
	PolicyWriter                 = domain.PolicyWriter
	AccountUsage                 = domain.AccountUsage
	ConcurrencyReader            = domain.ConcurrencyReader
	ConcurrencyWriter            = domain.ConcurrencyWriter
	EventInvokeConfig            = domain.EventInvokeConfig
	EventInvokeSettings          = domain.EventInvokeSettings
	FunctionURLCORS              = domain.FunctionURLCORS
	FunctionURLSettings          = domain.FunctionURLSettings
	FunctionURLRecord            = domain.FunctionURLRecord
	FunctionURLReader            = domain.FunctionURLReader
	FunctionURLWriter            = domain.FunctionURLWriter
	EventSourceMappingKey        = domain.EventSourceMappingKey
	EventSourceMappingRecord     = domain.EventSourceMappingRecord
	MappingOwner                 = domain.MappingOwner
	EventSourceMappingReader     = domain.EventSourceMappingReader
	EventSourceMappingWriter     = domain.EventSourceMappingWriter
	EventSourceMappingSettings   = domain.EventSourceMappingSettings
	EncryptedMappingFilters      = domain.EncryptedMappingFilters
	SQSProvisionedPollers        = domain.SQSProvisionedPollers
	StreamMappingSettings        = domain.StreamMappingSettings
	KafkaMappingSettings         = domain.KafkaMappingSettings
	KafkaIdentity                = domain.KafkaIdentity
	MQMappingSettings            = domain.MQMappingSettings
	MQIdentity                   = domain.MQIdentity
	DocumentDBMappingSettings    = domain.DocumentDBMappingSettings
	DocumentDBCheckpoint         = domain.DocumentDBCheckpoint
	StreamShardKey               = domain.StreamShardKey
	StreamShardRecord            = domain.StreamShardRecord
	StreamLane                   = domain.StreamLane
	StreamQueuedRecord           = domain.StreamQueuedRecord
	StreamBatch                  = domain.StreamBatch
	StreamReader                 = domain.StreamReader
	StreamWriter                 = domain.StreamWriter
	StreamFailure                = domain.StreamFailure
	InvocationRecord             = domain.InvocationRecord
	AsyncReader                  = domain.AsyncReader
	AsyncWriter                  = domain.AsyncWriter
	InvocationJob                = scheduler.Job
	OutcomeDeliveryRecord        = domain.OutcomeDeliveryRecord
	OutcomeReader                = domain.OutcomeReader
	OutcomeWriter                = domain.OutcomeWriter
	MetricPublicationKey         = domain.MetricPublicationKey
	MetricSample                 = domain.MetricSample
	MetricReader                 = domain.MetricReader
	MetricWriter                 = domain.MetricWriter
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
