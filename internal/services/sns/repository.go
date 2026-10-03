// Package sns owns topic authorization, subscriptions and retained publication.
package sns

import (
	"context"
	"errors"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

var ErrNotFound = errors.New("SNS resource not found")

type Scope struct{ Partition, AccountID, Region string }

type TopicKey struct {
	Scope
	Name string
}

func (k TopicKey) ARN() string {
	return "arn:" + k.Partition + ":sns:" + k.Region + ":" + k.AccountID + ":" + k.Name
}

type TopicRecord struct {
	Key              TopicKey
	ID               string
	Created, Updated time.Time
	DisplayName      string
	// Empty preserves an omitted attribute; notification signing defaults to 1.
	SignatureVersion string
	KmsMasterKeyID   string
	DeliveryPolicy   string
	// Empty preserves the native omission; both empty and PassThrough propagate.
	TracingConfig                   string
	FIFO, ContentBasedDeduplication bool
	FifoThroughputScope             string
	Sequence                        uint64
	Policy                          authorization.BoundPolicy
	Tags                            map[string]string
	Feedback                        map[string]FeedbackConfig
	Archive                         *ArchiveConfig
}

// FeedbackConfig belongs to a topic protocol. An omitted success sample rate
// remains distinct from an explicit zero when rendering native attributes.
type FeedbackConfig struct {
	SuccessRoleARN, FailureRoleARN string
	SuccessSampleRate              int
	SampleRateSet                  bool
}

// ArchiveConfig owns FIFO retention and the next hourly usage publication.
// Beginning is the enablement boundary, not the first archived message.
type ArchiveConfig struct {
	Policy               string
	RetentionDays        int32
	Beginning, MetricDue time.Time
}

// ArchiveEntry pins an immutable notification independently of deliveries.
// Sequence orders equal-timestamp publications; expiry follows topic retention.
type ArchiveEntry struct {
	TopicID            string
	Message            MessageKey
	Published, Expires time.Time
	Sequence           uint64
	SizeBytes          int64
}

type TopicQuery struct {
	Scope
	After string
	Limit int
}

type SubscriptionKey struct {
	Topic TopicKey
	ID    string
}

func (k SubscriptionKey) ARN() string { return k.Topic.ARN() + ":" + k.ID }

type SubscriptionRecord struct {
	Key SubscriptionKey
	// TopicID identifies membership in one topic incarnation. Native deletion
	// propagation may retain a separately addressable and routable subscription.
	TopicID                                 string
	Owner, PrincipalARN, Protocol, Endpoint string
	Created                                 time.Time
	Version                                 uint64
	RawMessageDelivery                      bool
	FilterPolicy, FilterScope, RedriveARN   string
	DeletionDue                             *time.Time
	// State is empty for active subscriptions, pending during confirmation,
	// and deleted while a cancellation token remains usable.
	State, SubscriptionRoleARN, DeliveryPolicy           string
	ConfirmationAuthenticated, AuthenticateOnUnsubscribe bool
	NextHTTPDelivery                                     time.Time
	Replay                                               ReplayRecord
}

// ReplayRecord is the subscription's current archive cursor. Policy preserves
// the accepted document. A zero End is unbounded; reaching an explicit end can
// leave delivery paused even after the public status becomes Completed.
type ReplayRecord struct {
	Policy, Status  string
	Start, End, Due time.Time
	Cursor          uint64
	Paused          bool
}

type ConfirmationRecord struct {
	Token        string
	Subscription SubscriptionKey
	Expires      time.Time
}

type TopicSubscriptionQuery struct {
	Topic TopicKey
	// Empty includes retained subscriptions from earlier topic incarnations.
	TopicID string
	After   string
	Limit   int
}

type OwnerSubscriptionQuery struct {
	Scope
	AfterARN string
	Limit    int
}

// MessageKey distinguishes protocol-specific bodies sharing one native
// publication ID. Empty Protocol is the default body shared by all endpoints
// without an override. Delivery and archive references retain these variants.
type MessageKey struct{ ID, Protocol string }

// MessageRecord is one immutable native notification body, shared by all
// matching deliveries and its archive entry. Signature fields are native protocol data.
type MessageRecord struct {
	Key   MessageKey
	Topic TopicKey
	Body  string
	// EncryptedBody replaces Body only; SNS metadata remains plaintext.
	EncryptedBody, WrappedDataKey []byte
	KMSKeyARN                     string
	// EncryptionContext is the immutable KMS binding used to wrap this key.
	EncryptionContext map[string]string
	// Publisher retains verified identity/session and transport tracing context,
	// never secret credentials. Cold live decryption forwards the identity;
	// archive decryption uses SNS, while delivery preserves transport tracing.
	Publisher                                 awsctx.Metadata
	MessageGroupID                            string
	MessageDeduplicationID, SequenceNumber    string
	Structured                                bool
	Subject                                   *string
	Attributes                                api.MessageAttributeMap
	Published                                 time.Time
	ParentEventID, RequestID                  string
	SignatureVersion, Signature, SigningKeyID string
	Type, Token, SubscribeURL                 string
}

type DeliveryRecord struct {
	ID           string
	Message      MessageKey
	Subscription SubscriptionKey
	Due          time.Time
	Version      uint64
	Attempts     int
	DeadLetter   bool
	// FIFO predecessor belongs to this subscription/group, not the SQS queue.
	FIFOGroup, FIFOPrevious string
	Replayed                bool
}

// DeduplicationKey uses a topic incarnation; recreation never inherits receipts.
type DeduplicationKey struct{ TopicID, Group, ID string }
type DeduplicationRecord struct {
	Key                       DeduplicationKey
	MessageID, SequenceNumber string
	Expires                   time.Time
}

// MetricPublicationKey groups SNS-owned samples into a completed UTC minute.
// Topic identity is a metric dimension, not a foreign key: pending statistics
// survive topic deletion and publish under the original account and region.
type MetricPublicationKey struct {
	Topic  TopicKey
	Minute time.Time
}

// MetricSample retains an identical-value weight, not a lossy statistic set.
// Native SNS exposes percentiles, so distinct publication sizes must survive.
type MetricSample struct {
	Name               string
	Value, SampleCount int64
}

// SigningKeyRecord belongs to the instance's SNS transport, not an AWS account
// resource. The retained key and certificate keep queued signatures fetchable
// across process restart; PublicEndpoint remains operator-owned configuration.
type SigningKeyRecord struct {
	ID                            string
	PrivateKeyDER, CertificatePEM []byte
}

type Reader interface {
	Context() context.Context
	Topic(TopicKey) (TopicRecord, error)
	Topics(TopicQuery) ([]TopicRecord, error)
	TopicCount(Scope) (int64, error)
	Subscription(SubscriptionKey) (SubscriptionRecord, error)
	SubscriptionByEndpoint(topicID, protocol, endpoint string) (SubscriptionRecord, error)
	Confirmation(string) (ConfirmationRecord, error)
	SubscriptionsByTopic(TopicSubscriptionQuery) ([]SubscriptionRecord, error)
	// Public owner listings include membership in current topic incarnations.
	SubscriptionsByOwner(OwnerSubscriptionQuery) ([]SubscriptionRecord, error)
	SubscriptionCount(topicID string) (int64, error)
	// FilterPolicyCount selects one topic incarnation, or the subscriber-owner
	// account when topicID is empty. Stored filter JSON is compact canonical JSON.
	FilterPolicyCount(Scope, string) (int64, error)
	Message(MessageKey) (MessageRecord, error)
	Delivery(string) (DeliveryRecord, error)
	NextDelivery() (scheduler.Job, bool, error)
	NextSubscriptionDeletion() (scheduler.Job, bool, error)
	ArchiveEntry(MessageKey) (ArchiveEntry, error)
	NextArchiveEntry(topicID string, start time.Time, after uint64) (ArchiveEntry, bool, error)
	NextArchiveExpiration() (ArchiveEntry, bool, error)
	ArchiveUsage(topicID string) (messages, bytes int64, err error)
	NextArchiveMetric() (TopicRecord, bool, error)
	NextReplay() (SubscriptionRecord, bool, error)
	SigningKey() (SigningKeyRecord, error)
	Deduplication(DeduplicationKey) (DeduplicationRecord, error)
	DeliveryTail(SubscriptionKey, string) (string, error)
	NextMetricPublication() (MetricPublicationKey, error)
	MetricSamples(MetricPublicationKey) ([]MetricSample, error)
}

type Transaction interface {
	Reader
	PutTopic(TopicRecord) error
	DeleteTopic(TopicKey) error
	PutSubscription(SubscriptionRecord) error
	// Confirmation tokens outlive physical subscription deletion until expiry.
	PutConfirmation(ConfirmationRecord) error
	// DeleteExpiredConfirmations prunes tokens when another confirmation is issued.
	DeleteExpiredConfirmations(time.Time) error
	// OrphanTopicSubscriptions advances versions and schedules deletion without
	// making the old subscription ID a member of a recreated topic.
	OrphanTopicSubscriptions(topicID string, due time.Time) error
	// DeleteSubscription also removes its retained deliveries and orphaned messages.
	DeleteSubscription(SubscriptionKey) error
	// DeleteSubscriptionNotifications cancels admitted publications, preserving
	// the subscription's independent confirmation tokens and control deliveries.
	DeleteSubscriptionNotifications(SubscriptionKey) error
	PutMessage(MessageRecord) error
	// A delivery ID retains its original Message key across retries.
	PutDelivery(DeliveryRecord) error
	// DeleteDelivery collects its message when no delivery or archive references it.
	DeleteDelivery(string) error
	PutArchiveEntry(ArchiveEntry) error
	DeleteArchiveEntry(MessageKey) error
	DeleteArchiveEntries(topicID string) error
	// UpdateArchiveRetention expires old entries before extending surviving deadlines.
	UpdateArchiveRetention(topicID string, days int32, now time.Time) error
	PutSigningKey(SigningKeyRecord) error
	PutDeduplication(DeduplicationRecord) error
	DeleteExpiredDeduplication(topicID string, now time.Time) error
	NextTopicSequence(TopicKey) (uint64, error)
	// AddMetricSamples merges weights only for identical metric names and values.
	AddMetricSamples(MetricPublicationKey, []MetricSample) error
	DeleteMetricPublication(MetricPublicationKey) error
}

// Repository shares the instance transaction domain with the journal and other
// typed service repositories. External delivery and key generation happen outside
// resource transactions.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	// Attempt rolls back a rejected publication's related writes without
	// aborting a caller that handles it; acceptance still joins the caller.
	Attempt(context.Context, func(Transaction) error) error
}
