package lambda

import "time"

// EventSourceMappingKey identifies a mapping independently of its function's lifetime.
type EventSourceMappingKey struct {
	Scope
	UUID string
}

func (k EventSourceMappingKey) ARN() string {
	return "arn:" + k.Partition + ":lambda:" + k.Region + ":" + k.Account + ":event-source-mapping:" + k.UUID
}

// SQSProvisionedPollers bounds the dedicated queue consumers for one mapping.
type SQSProvisionedPollers struct{ Minimum, Maximum int }

// EventSourceMappingSettings keeps shared batching and source-owned options.
type EventSourceMappingSettings struct {
	BatchSize               int
	BatchingWindow          time.Duration
	ReportBatchItemFailures bool
	Filters                 []string
	KMSKeyARN               string
	EncryptedFilters        *EncryptedMappingFilters
	MaximumConcurrency      *int
	ProvisionedPollers      *SQSProvisionedPollers
	Metrics                 []string
	Stream                  *StreamMappingSettings
	Kafka                   *KafkaMappingSettings
	MQ                      *MQMappingSettings
	DocumentDB              *DocumentDBMappingSettings
}

// FilterEnvelopeSDK identifies signed AWS Encryption SDK filter ciphertext.
// An empty format on retained records identifies the legacy AES-GCM envelope.
const FilterEnvelopeSDK = "aws-encryption-sdk-v2"

// EncryptedMappingFilters retains only envelope ciphertext and its KMS context.
// Filters is empty whenever this envelope is present.
type EncryptedMappingFilters struct {
	Content, DataKey []byte
	FunctionARN      string
	Format           string
}

// StreamMappingSettings owns stream positioning, failure and window behavior.
// A negative MaximumRecordAge or MaximumRetryAttempts means no configured limit;
// Source retention remains the upper bound on record eligibility.
type StreamMappingSettings struct {
	StartingPosition           string
	StartingPositionTimestamp  time.Time
	ParallelizationFactor      int
	MaximumRetryAttempts       int
	MaximumRecordAge           time.Duration
	BisectBatchOnFunctionError bool
	TumblingWindow             time.Duration
	OnFailure                  string
}

type EventSourceMappingRecord struct {
	Key                          EventSourceMappingKey
	Owner                        MappingOwner
	Function                     FunctionReference
	EventSourceARN               string
	Version                      uint64
	State, StateTransitionReason string
	LastProcessingResult         string
	TransitionState              string
	LastModified, TransitionAt   time.Time
	Settings                     EventSourceMappingSettings
	Tags                         map[string]string
}

type EventSourceMappingReader interface {
	EventSourceMapping(EventSourceMappingKey) (EventSourceMappingRecord, error)
	EventSourceMappings(Scope) ([]EventSourceMappingRecord, error)
	AllEventSourceMappings() ([]EventSourceMappingRecord, error)
}

type EventSourceMappingWriter interface {
	PutEventSourceMapping(EventSourceMappingRecord) error
	SetEventSourceMappingProcessingResult(EventSourceMappingKey, string) error
	DeleteEventSourceMapping(EventSourceMappingKey) error
}
