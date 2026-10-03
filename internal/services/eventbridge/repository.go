package eventbridge

import (
	"context"
	"errors"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/services/eventbridge/inputtransform"
)

var ErrNotFound = errors.New("EventBridge resource not found")

// Scope is the complete regional ownership boundary of an event bus.
type Scope struct{ Partition, Account, Region string }
type BusKey struct {
	Scope
	Name string
}
type RuleKey struct {
	Bus  BusKey
	Name string
}

type BusRecord struct {
	Key                             BusKey
	Description                     string
	KmsKeyIdentifier, DeadLetterARN string
	ConfigurationDataKey            []byte
	ConfigurationKeyARN             string
	Tags                            map[string]string
	Policy                          authorization.BoundPolicy
	Created, Modified               time.Time
}
type RuleRecord struct {
	Key RuleKey
	// ManagedBy identifies the service owner, including a targetless managed rule.
	ManagedBy string
	// ArchiveID separately identifies archive-owned rule and delivery lifetimes.
	ArchiveID                                         string
	Pattern, Description, State, CreatedBy            string
	EncryptedPattern                                  []byte
	RoleARN, ScheduleExpression                       string
	HasPattern, HasDescription, HasScheduleExpression bool
	NextSchedule                                      *time.Time
	Tags                                              map[string]string
}
type TargetRecord struct {
	Rule                                   RuleKey
	ID, ARN, MessageGroupID, DeadLetterARN string
	RoleARN                                string
	Input                                  inputtransform.Definition
	EncryptedConfiguration                 []byte
	EcsParameters                          *api.EcsParameters
	KinesisParameters                      *api.KinesisParameters
	HttpParameters                         *api.HttpParameters
	MaxRetries, MaxAgeSeconds              int
	HasRetryPolicy                         bool
	HasMaxRetries, HasMaxAge               bool
}

// EventRecord retains the admitted AWS event independently of rule lifetimes.
// Detail is customer JSON, not serialized resource state.
type EventRecord struct {
	// TODO: Comeback implement bounded accepted-event and terminal-delivery retention without removing history needed by pending deliveries.
	// ID identifies this admission and its causal children. WireID can be
	// preserved when a separate admission forwards the same native event.
	ID, WireID                    string
	ReplayName                    string
	Bus                           BusKey
	Source, DetailType, Detail    string
	Resources                     []string
	Time, Accepted                time.Time
	Account                       string
	Region                        string
	SameRegionHop, CrossRegionHop bool
	RequestID, ActorARN           string
	// TraceHeader is AWS X-Ray metadata, never customer JSON or causal identity.
	TraceHeader string
	// Payload holds the entire customer event when encrypted. Detail is then
	// empty; metadata and transport trace remain independently available.
	Payload                  ArchivePayload
	KeyARN, BusDeadLetterARN string
	ConfigurationDataKey     []byte
	ConfigurationKeyARN      string
}

// DeliveryRecord is one retained target invocation. Configuration is captured
// at admission; each result advances Version and commits the next deadline.
type DeliveryRecord struct {
	ID, EventID, RuleARN, TargetID, TargetARN string
	// ArchiveID routes retained managed-target work to the owning archive.
	ArchiveID                              string
	Input, MessageGroupID, DeadLetterARN   string
	RoleARN                                string
	HasInput                               bool
	BusProcessing                          bool
	RulePattern, TargetConfiguration       []byte
	RuleMatched, MatchOnly                 bool
	EcsParameters                          *api.EcsParameters
	KinesisParameters                      *api.KinesisParameters
	HttpParameters                         *api.HttpParameters
	MaxRetries, MaxAgeSeconds, Attempts    int
	Due                                    time.Time
	Version                                uint64
	State, LastErrorCode, LastErrorMessage string
	ExhaustedRetryCondition                string
}

// Reader returns detached records. Context borrows the transaction for related
// IAM and journal calls and is valid only for the repository callback.
type Reader interface {
	ArchiveReader
	ReplayReader
	MetricReader
	ConnectionReader
	APIDestinationReader
	Context() context.Context
	Bus(BusKey) (BusRecord, error)
	Buses(Scope) ([]BusRecord, error)
	Rule(RuleKey) (RuleRecord, error)
	Rules(BusKey) ([]RuleRecord, error)
	NextScheduledRule() (RuleRecord, bool, error)
	Targets(RuleKey) ([]TargetRecord, error)
	RuleNamesByTarget(BusKey, string) ([]string, error)
	Event(string) (EventRecord, error)
	Delivery(string) (DeliveryRecord, error)
	NextDelivery() (DeliveryRecord, bool, error)
	EventDeliveries(string) ([]DeliveryRecord, error)
}

type Transaction interface {
	Reader
	ArchiveWriter
	ReplayWriter
	MetricWriter
	ConnectionWriter
	APIDestinationWriter
	PutBus(BusRecord) error
	DeleteBus(BusKey) error
	PutRule(RuleRecord) error
	UpdateRuleSchedule(RuleKey, *time.Time) error
	DeleteRule(RuleKey) error
	PutTarget(TargetRecord) error
	DeleteTarget(RuleKey, string) error
	PutEvent(EventRecord) error
	PutDelivery(DeliveryRecord) error
}

// Repository callbacks own serializable transactions. Callback, cancellation,
// and commit errors roll back all related resource, event and delivery writes.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
}
