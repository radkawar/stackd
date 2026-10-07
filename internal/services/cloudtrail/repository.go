package cloudtrail

import (
	"context"
	"errors"
	"time"

	"stackd/internal/scheduler"
)

var ErrNotFound = errors.New("CloudTrail resource not found")

type Scope struct{ Partition, AccountID, Region string }
type TrailKey struct {
	Scope
	Name string
}

func (k TrailKey) ARN() string {
	return "arn:" + k.Partition + ":cloudtrail:" + k.Region + ":" + k.AccountID + ":trail/" + k.Name
}

// Selection is validated service-owned configuration. Exactly one family is
// populated. Basic defaults are resolved before persistence, not at evaluation.
type Selection struct {
	Basic    []BasicSelector
	Advanced []AdvancedSelector
}

type BasicSelector struct {
	// ReadOnly nil selects both reads and writes.
	ReadOnly          *bool
	IncludeManagement bool
	ExcludedSources   []string
	DataResources     []DataResource
}

type DataResource struct {
	Type        string
	ARNPrefixes []string
}

type AdvancedSelector struct {
	Name   string
	Fields []FieldSelector
}

type FieldSelector struct {
	Field string
	Tests []FieldTest
}

type FieldTest struct {
	// Operator is one of Equals, StartsWith, EndsWith and their Not variants.
	Operator string
	Values   []string
}

type TrailRecord struct {
	Key TrailKey
	// ID fences delete/recreate independently of the reusable trail ARN.
	ID string
	// CFNOwner is a private creation claim, never supplied or changed by tags.
	CFNOwner string
	// OrganizationID binds management-owned trails to their organization lifetime.
	OrganizationID string
	Bucket, Prefix string
	// KMSKeyID is the canonical key ARN after destination admission; empty uses SSE-S3.
	KMSKeyID string
	// SNSTopicName preserves the configured name or ARN returned by the trail APIs.
	SNSTopicName                                          string
	LogsGroupARN, LogsRoleARN                             string
	IncludeGlobal, MultiRegion, RecursiveLogging, Logging bool
	LogFileValidation                                     bool
	Created, Modified                                     time.Time
	Started, Stopped                                      *time.Time
	// StopAfter retains effective admission while a stop propagates, without
	// changing the desired IsLogging status returned by the API.
	StopAfter *time.Time
	Selection Selection
	Tags      map[string]string
}

// DestinationKind identifies retained log or notification work.
type DestinationKind string

const (
	DestinationS3     DestinationKind = "s3"
	DestinationLogs   DestinationKind = "logs"
	DestinationDigest DestinationKind = "digest"
	DestinationSNS    DestinationKind = "sns"
)

// DeliveryStatus retains native status after a successful batch is removed.
type DeliveryStatus struct {
	TrailID                  string
	Destination              DestinationKind
	LastAttempt, LastSuccess *time.Time
	LastError                string
}

// DeliveryRecord groups references to immutable journal API events, not copied
// event documents. An unsealed batch accepts events until Due. Sealing commits
// before external delivery, so retries always send the same records and object key.
// A crash before completion can repeat a destination write; it cannot lose the batch.
// After S3 succeeds, the same work item advances to its SNS notification without
// rewriting the log object when publication fails.
type DeliveryRecord struct {
	ID                                   string
	Trail                                TrailKey
	TrailID                              string
	Destination                          DestinationKind
	LogsGroupARN, LogsRoleARN            string
	OrganizationID                       string
	AccountID, Region, Bucket, ObjectKey string
	Created, Due, Expires                time.Time
	Sealed                               bool
	EventCount, Attempts                 int
	// DigestSignature is supplied only by the digest executor from retained pending work.
	DigestSignature string
	Version         uint64
}

type Reader interface {
	DigestReader
	Context() context.Context
	Trail(TrailKey) (TrailRecord, error)
	TrailByOwner(partition, region, name, owner string) (TrailRecord, error)
	Trails(partition, accountID string) ([]TrailRecord, error)
	HasOrganizationTrails(partition string) (bool, error)
	DeliveryStatus(trailID string, kind DestinationKind) (DeliveryStatus, error)
	Delivery(id string) (DeliveryRecord, error)
	OpenDelivery(trailID, accountID, region string, kind DestinationKind) (DeliveryRecord, error)
	DeliveryEventIDs(id string) ([]string, error)
	NextDelivery() (scheduler.Job, bool, error)
}

type Transaction interface {
	Reader
	DigestTransaction
	PutTrail(TrailRecord) error
	DeleteTrail(TrailKey) error
	PutDeliveryStatus(DeliveryStatus) error
	PutDelivery(DeliveryRecord) error
	AppendDeliveryEvent(deliveryID, eventID string) error
	DeleteDelivery(id string) error
}

// Repository joins the native instance transaction. Admission uses current
// selectors and logging state in the same commit as the source API event.
// Callbacks and their contexts cannot outlive the enclosing transaction.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
}
