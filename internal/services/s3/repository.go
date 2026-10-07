package s3

import (
	"context"
	"errors"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/scheduler"
)

var ErrNotFound = errors.New("S3 resource not found")

// BucketKey is a partition-wide namespace. Ownership and location belong to the
// bucket, not the requester's account or signing region.
type BucketKey struct{ Partition, Name string }

func (k BucketKey) ARN() string { return "arn:" + k.Partition + ":s3:::" + k.Name }

// AccessPointKey identifies an ordinary regional access point.
type AccessPointKey struct{ Partition, AccountID, Region, Name string }

func (k AccessPointKey) ARN() string {
	return "arn:" + k.Partition + ":s3:" + k.Region + ":" + k.AccountID + ":accesspoint/" + k.Name
}

type AccessPointRecord struct {
	Key             AccessPointKey
	Alias           string
	Bucket          BucketKey
	BucketAccountID string
	Created         time.Time
	VPCID           string
	PublicAccess    PublicAccessBlock
	Policy          authorization.BoundPolicy
	// CloudFormationOwner is the private claim of the AWS::S3::AccessPoint
	// incarnation that created this access point. Public tags cannot set it,
	// and it never reaches an AWS response. Empty means a direct-API access point.
	CloudFormationOwner string
}

// AccessPointQuery selects names in lexical order, exclusively after After.
// Bucket optionally filters the backing bucket name. Limit must be positive.
type AccessPointQuery struct {
	Partition, AccountID, Region, Bucket, After string
	Limit                                       int
}

type ObjectKey struct {
	Bucket BucketKey
	Name   string
}

func (k ObjectKey) ARN() string { return k.Bucket.ARN() + "/" + k.Name }

// ObjectVersionKey identifies immutable history; "null" is the replaceable slot.
type ObjectVersionKey struct {
	ObjectKey
	VersionID string
}

type PublicAccessBlock struct {
	BlockPublicACLs, IgnorePublicACLs, BlockPublicPolicy, RestrictPublicBuckets bool
}

// ACLGrant retains canonical and group grants, including duplicate grants.
type ACLGrant struct {
	Type, ID, URI, Permission string
}

// AccessControlList is original ownership, never the BOE/public-access mask.
// A non-nil ACL with no grants is distinct from the legacy nil default.
type AccessControlList struct {
	OwnerAccountID, OwnerID string
	Grants                  []ACLGrant
}

type BucketRecord struct {
	Key               BucketKey
	AccountID, Region string
	// Incarnation is generated once at creation and survives metadata updates.
	Incarnation string
	// CloudFormationOwner is the private claim of the AWS::S3::Bucket
	// incarnation that created this bucket. It is fixed at creation, cannot be
	// set through tags or wire input, and never reaches an AWS response.
	CloudFormationOwner string
	// PolicyOwner is the private claim of the AWS::S3::BucketPolicy incarnation
	// that attached the current policy. Public DeleteBucketPolicy clears it.
	PolicyOwner       string
	Created           time.Time
	Policy            authorization.BoundPolicy
	PublicAccess      *PublicAccessBlock
	Ownership         string
	ACL               *AccessControlList
	Versioning        string
	ObjectLockEnabled bool
	DefaultRetention  DefaultRetention
	RequesterPays     bool
	ABACEnabled       bool
	// Empty means acceleration has never been configured.
	AccelerationStatus  string
	EncryptionAlgorithm string
	BucketKeyEnabled    bool
	SSECustomerBlocked  bool
	// KMSKeyID retains the literal default identifier, resolved at object write.
	KMSKeyID string
}

// Tag is a case-sensitive key/value pair. Bucket, object-version and access-point
// tag sets have separate ownership and authorization.
type Tag struct{ Key, Value string }

// CustomerKeyVerifier proves possession of an SSE-C key without retaining it.
// MD5 is response metadata; Salt and Hash are the private key verifier.
type CustomerKeyVerifier struct {
	Salt []byte
	Hash []byte
	MD5  string
}

// ObjectRecord is version metadata. Ciphertext is held separately so listing
// objects does not read or copy customer payloads.
// EncryptionKey is private raw SSE-S3 data-key material or a KMS-wrapped data key,
// selected by EncryptionAlgorithm, never an API response.
type ObjectRecord struct {
	Key       ObjectKey
	VersionID string
	ACL       *AccessControlList
	Sequence  int64
	// CreatedOrder determines current-version and listing order. Multipart
	// initiation reserves it before the later publication Sequence exists.
	CreatedOrder int64
	UploadID     string
	DeleteMarker bool
	// Replica origin survives transient metadata-replication status changes.
	Replica  bool
	Modified time.Time
	Size     int64
	// Empty is STANDARD; nonstandard classes retain their native spelling.
	StorageClass                                    string
	ETag, ChecksumAlgorithm, Checksum, ChecksumType string
	// Retains initiation checksum provenance for completed SSE-C upload retries.
	MultipartChecksumExplicit                     bool
	ContentType, ContentEncoding, ContentLanguage string
	ContentDisposition, CacheControl              string
	WebsiteRedirectLocation                       string
	Expires                                       *time.Time
	// Tiering is present only for monitored Intelligent-Tiering versions.
	Tiering             *ObjectTiering
	Retention           ObjectRetention
	LegalHold           string
	LegalHoldModified   time.Time
	Metadata            map[string]string
	EncryptionAlgorithm string
	// KMSKeyARN is the canonical key ARN resolved when the object was written.
	KMSKeyARN         string
	EncryptionContext map[string]string
	// Returned only by Object and ObjectVersion, never metadata listings.
	EncryptionKey []byte
	// SSE-C retains only this verifier, never a customer key in EncryptionKey.
	CustomerKey *CustomerKeyVerifier
}

func (v ObjectRecord) VersionKey() ObjectVersionKey {
	return ObjectVersionKey{ObjectKey: v.Key, VersionID: v.VersionID}
}

// VersionQuery scans keys ascending and each key's history newest first.
// AfterVersion selects the exclusive position within AfterKey; empty skips that key.
type VersionQuery struct {
	Bucket                         BucketKey
	Prefix, AfterKey, AfterVersion string
	// AfterOrder is an internal immutable cursor for scans that delete their
	// last visited version. When present it replaces AfterVersion resolution.
	AfterOrder *int64
	Limit      int
}

// ObjectQuery selects metadata in binary key order. After is exclusive; Prefix
// and After operate on the original object key, not an encoded URL spelling.
// Limit must be positive. Listings omit private EncryptionKey material.
type ObjectQuery struct {
	Bucket        BucketKey
	Prefix, After string
	Limit         int
}

// Reader returns detached values from the current transaction. Context borrows
// the same authority for IAM decisions and committed API observations.
type Reader interface {
	ReplicationMetricReader
	TieringReader
	RequestMetricsReader
	InventoryReader
	AnalyticsReader
	Context() context.Context
	// AccountPublicAccessBlock returns nil when the account has no configuration.
	AccountPublicAccessBlock(partition, accountID string) (*PublicAccessBlock, error)
	AccessPoint(AccessPointKey) (AccessPointRecord, error)
	AccessPointAlias(partition, alias string) (AccessPointRecord, error)
	AccessPoints(AccessPointQuery) ([]AccessPointRecord, error)
	AccessPointCount(partition, accountID, region string) (int, error)
	AccessPointTags(AccessPointKey) ([]Tag, error)
	Bucket(BucketKey) (BucketRecord, error)
	Buckets(partition, accountID string) ([]BucketRecord, error)
	BucketTags(BucketKey) ([]Tag, error)
	// Browser configurations are loaded only by their controls/HTTP consumers.
	// An absent configuration returns nil without a storage error.
	BucketCORS(BucketKey) ([]CORSRule, error)
	BucketWebsite(BucketKey) (*WebsiteConfiguration, error)
	BucketLogging(BucketKey) (*LoggingConfiguration, error)
	// BucketReplication returns nil when no configuration is present.
	BucketReplication(BucketKey) (*ReplicationConfiguration, error)
	BucketLifecycle(BucketKey) (*LifecycleConfiguration, error)
	NextLifecycleScan() (*BucketScan, error)
	ReplicationStates(ObjectVersionKey) ([]ReplicationState, error)
	ReplicationJob(int64) (ReplicationJob, error)
	NextReplicationJob() (*ReplicationJob, error)
	ReplicationJobs(ObjectVersionKey) ([]ReplicationJob, error)
	ObjectTags(ObjectVersionKey) ([]Tag, error)
	Object(ObjectKey) (ObjectRecord, error)
	ObjectVersion(ObjectVersionKey) (ObjectRecord, error)
	ObjectVersions(VersionQuery) ([]ObjectRecord, error)
	Objects(ObjectQuery) ([]ObjectRecord, error)
	// Restore state belongs to the retained version, never a copy or upload.
	ObjectRestore(ObjectVersionKey) (*ObjectRestore, error)
	NextObjectRestore() (*ObjectRestore, error)
	// ObjectData returns detached encrypted parts in published order.
	ObjectData(ObjectVersionKey) ([][]byte, error)
	ObjectParts(ObjectVersionKey) ([]PartRecord, error)
	MultipartUpload(MultipartUploadKey) (MultipartUploadRecord, error)
	MultipartUploads(MultipartQuery) ([]MultipartUploadRecord, error)
	MultipartParts(MultipartUploadKey, int32, int) ([]PartRecord, error)
	CompletedMultipartUpload(MultipartUploadKey) (ObjectRecord, error)
	NotificationState(BucketKey) (NotificationState, error)
	NextNotificationChange() (scheduler.Job, bool, error)
	NotificationDelivery(string) (NotificationDelivery, error)
	NextNotificationDelivery() (scheduler.Job, bool, error)
	AccessLogDelivery(string) (AccessLogDelivery, error)
	NextAccessLogDelivery() (scheduler.Job, bool, error)
}

type Transaction interface {
	Reader
	ReplicationMetricWriter
	TieringWriter
	RequestMetricsWriter
	InventoryWriter
	AnalyticsWriter
	PutAccountPublicAccessBlock(partition, accountID string, block PublicAccessBlock) error
	DeleteAccountPublicAccessBlock(partition, accountID string) error
	PutAccessPoint(AccessPointRecord) error
	DeleteAccessPoint(AccessPointKey) error
	PutAccessPointTags(AccessPointKey, []Tag) error
	PutBucket(BucketRecord) error
	DeleteBucket(BucketKey) error
	ReplaceBucketTags(BucketKey, []Tag) error
	ReplaceBucketCORS(BucketKey, []CORSRule) error
	ReplaceBucketWebsite(BucketKey, *WebsiteConfiguration) error
	ReplaceBucketLogging(BucketKey, *LoggingConfiguration) error
	ReplaceBucketReplication(BucketKey, *ReplicationConfiguration) error
	ReplaceBucketLifecycle(BucketKey, *LifecycleConfiguration) error
	AdvanceLifecycleScan(BucketKey, time.Time) error
	// Older completion sequences cannot overwrite a newer accepted attempt.
	PutReplicationState(ReplicationState) error
	// A zero Sequence allocates from the existing transaction sequencer.
	PutReplicationJob(*ReplicationJob) error
	DeleteReplicationJob(int64) error
	// PutReplica adopts immutable ciphertext/part records from the source,
	// preserving the supplied version, creation order and notification sequence.
	// The destination owns its data independently of subsequent source deletion.
	PutReplica(ObjectVersionKey, ObjectRecord) error
	ReplaceObjectTags(ObjectVersionKey, []Tag) error
	ReplaceObjectACL(ObjectVersionKey, AccessControlList) error
	ReplaceObjectRetention(ObjectVersionKey, ObjectRetention) error
	ReplaceObjectLegalHold(ObjectVersionKey, string, time.Time) error
	PutObjectRestore(ObjectRestore) error
	DeleteObjectRestore(ObjectVersionKey) error
	// TransitionObject changes only storage class and notification sequence.
	// Version identity, creation time, encryption and payload remain intact.
	TransitionObject(ObjectVersionKey, string) (int64, error)
	// Object content mutations return their transaction-ordered notification sequencer.
	PutObject(ObjectRecord, []byte) (int64, error)
	DeleteObject(ObjectVersionKey) (int64, error)
	// PutMultipartUpload assigns initiation order and an opaque upload ID.
	PutMultipartUpload(*MultipartUploadRecord) error
	PutMultipartPart(MultipartUploadKey, PartRecord, []byte) error
	DeleteMultipartUpload(MultipartUploadKey) error
	// CompleteMultipartUpload consumes the upload and returns its publication
	// sequencer. Retained versions adopt selected ciphertext without decrypting
	// or copying it through the service. Invisible completions still emit events.
	CompleteMultipartUpload(MultipartUploadKey, ObjectRecord, []int32, bool) (int64, error)
	PutNotificationState(NotificationState) error
	PutNotificationDelivery(NotificationDelivery) error
	DeleteNotificationDelivery(string) error
	PutAccessLogDelivery(AccessLogDelivery) error
	DeleteAccessLogDelivery(string) error
}

// Repository shares the instance transaction domain. Resource state, current
// authorization and API events commit together or all roll back. Handles cannot
// outlive callbacks; writers copy caller-owned maps, slices and pointers.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
