// Package configservice owns AWS Config recording, retained configuration history,
// delivery, rules and aggregate views. Resource owners remain authoritative.
package configservice

import (
	"context"
	api "stackd/internal/awsapi/configservice"
	"time"
)

type Scope struct{ Partition, AccountID, Region string }

// Recorder is the customer-managed recorder and its observed execution status.
type Recorder struct {
	Scope
	Name, ARN, RoleARN                          string
	AllSupported, IncludeGlobal, Recording      bool
	ResourceTypes, ExcludedTypes                []string
	LastStart, LastStop, LastStatusChange       time.Time
	LastStatus, LastErrorCode, LastErrorMessage string
}

type Channel struct {
	Scope
	Name, Bucket, Prefix, KMSKeyARN, TopicARN, Frequency string
	LastAttempt, LastSuccess, NextDelivery               time.Time
	Status, ErrorCode, ErrorMessage                      string
}

// Item is an immutable configuration observation, not a second mutable resource.
// Configuration and supplementary strings are native Config JSON documents.
type Item struct {
	Scope
	Sequence                                                      int64
	ResourceType, ResourceID, ResourceName, ARN, AvailabilityZone string
	CaptureTime, CreationTime                                     time.Time
	Status, Configuration                                         string
	Tags, Supplementary                                           map[string]string
	Relationships                                                 []Relationship
}
type Relationship struct{ ResourceType, ResourceID, ResourceName, Name string }

type Delivery struct {
	Scope
	ID, ChannelName, Kind, ObjectKey string
	Due, CreatedAt, CompletedAt      time.Time
	Status, ErrorCode, ErrorMessage  string
	Attempts                         int
	FirstSequence, LastSequence      int64
}

type Rule struct {
	SourceMessages []string
	Scope
	Name, ID, ARN, Description, Owner, SourceIdentifier, InputParameters string
	ResourceTypes                                                        []string
	ResourceID, TagKey, TagValue                                         string
	CreatedAt, LastEvaluation, LastReevaluation                          time.Time
	ErrorCode, ErrorMessage                                              string
}
type Evaluation struct {
	Scope
	RuleName, ResourceType, ResourceID, ComplianceType, Annotation string
	OrderingTime, RecordedAt, InvokedAt                            time.Time
}
type EvaluationRun struct {
	Scope
	Token, RuleName                 string
	ItemSequence                    int64
	Due, CreatedAt, CompletedAt     time.Time
	Status, ErrorCode, ErrorMessage string
}
type Aggregator struct {
	Scope
	Name, ARN            string
	CreatedAt, UpdatedAt time.Time
	Sources              []AggregationSource
}
type AggregationSource struct{ AccountID, Region string }
type AggregationAuthorization struct {
	Scope
	AccountID, Region, ARN string
	CreatedAt              time.Time
}

type Reader interface {
	Context() context.Context
	Tags(Scope, string) (map[string]string, error)
	Recorder(Scope) (Recorder, bool, error)
	Channel(Scope) (Channel, bool, error)
	Items(Scope) ([]Item, error)
	Deliveries() ([]Delivery, error)
	Rules(Scope) ([]Rule, error)
	Evaluations(Scope) ([]Evaluation, error)
	EvaluationRuns() ([]EvaluationRun, error)
	Aggregators(Scope) ([]Aggregator, error)
	AggregationAuthorizations(Scope) ([]AggregationAuthorization, error)
}
type Transaction interface {
	Reader
	// PutTags replaces the tags for a complete resource ARN; empty tags clear it.
	PutTags(Scope, string, map[string]string) error
	PutRecorder(Recorder) error
	DeleteRecorder(Scope) error
	PutChannel(Channel) error
	DeleteChannel(Scope) error
	AppendItem(Item) (Item, error)
	PutDelivery(Delivery) error
	PutRule(Rule) error
	DeleteRule(Scope, string) error
	PutEvaluation(Evaluation) error
	DeleteEvaluations(Scope, string) error
	PutEvaluationRun(EvaluationRun) error
	PutAggregator(Aggregator) error
	DeleteAggregator(Scope, string) error
	PutAggregationAuthorization(AggregationAuthorization) error
	DeleteAggregationAuthorization(Scope, string, string) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// Resources lists real scoped owner snapshots. It must never derive configuration
// from API request/response echoes. Empty service selects all supported owners.
type Resources interface {
	List(context.Context, string) ([]Item, error)
	SupportedTypes() []string
}

// Effects keeps current IAM, S3, SNS and actual Lambda execution in their owners.
// AuthorizeCapture borrows the source transaction and performs no external I/O;
// every other method runs outside Config storage transactions.
type Effects interface {
	AuthorizeCapture(context.Context, Recorder, Item) error
	ValidateRole(context.Context, string) error
	ValidateChannel(context.Context, Recorder, Channel) error
	Deliver(context.Context, Recorder, Channel, string, []byte) error
	Notify(context.Context, Recorder, Channel, []byte) error
	InvokeRule(context.Context, Rule, []byte) error
}

func (i Item) ConfigurationItem() api.ConfigurationItem {
	out := api.ConfigurationItem{AccountId: new(api.AccountId(i.AccountID)), Arn: new(api.ARN(i.ARN)), AwsRegion: new(api.AwsRegion(i.Region)), ConfigurationItemCaptureTime: &i.CaptureTime, ConfigurationItemStatus: new(api.ConfigurationItemStatus(i.Status)), ResourceId: new(api.ResourceId(i.ResourceID)), ResourceType: new(api.ResourceType(i.ResourceType)), Version: new(api.Version("1.3")), ConfigurationStateId: new(api.ConfigurationStateId(sequenceID(i.Sequence))), Tags: api.Tags{}, SupplementaryConfiguration: api.SupplementaryConfiguration{}, Relationships: api.RelationshipList{}, RelatedEvents: api.RelatedEventList{}}
	out.ConfigurationItemMD5Hash = new(api.ConfigurationItemMD5Hash(""))
	if i.ResourceName != "" {
		out.ResourceName = new(api.ResourceName(i.ResourceName))
	}
	if i.AvailabilityZone != "" {
		out.AvailabilityZone = new(api.AvailabilityZone(i.AvailabilityZone))
	}
	if !i.CreationTime.IsZero() {
		out.ResourceCreationTime = &i.CreationTime
	}
	if i.Configuration != "" {
		out.Configuration = new(api.Configuration(i.Configuration))
	}
	for k, v := range i.Tags {
		out.Tags[api.Name(k)] = api.Value(v)
	}
	for k, v := range i.Supplementary {
		out.SupplementaryConfiguration[api.SupplementaryConfigurationName(k)] = api.SupplementaryConfigurationValue(v)
	}
	for _, r := range i.Relationships {
		out.Relationships = append(out.Relationships, api.Relationship{ResourceType: new(api.ResourceType(r.ResourceType)), ResourceId: new(api.ResourceId(r.ResourceID)), ResourceName: new(api.ResourceName(r.ResourceName)), RelationshipName: new(api.RelationshipName(r.Name))})
	}
	return out
}
