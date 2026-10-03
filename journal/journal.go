// Package journal exposes committed service events for local inspection.
// Events share the resource transaction; they are not a replay or delivery log.
package journal

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidQuery = errors.New("event cursor must be nonnegative and limit must be between 1 and 1000")

// ValidateQuery owns the query bounds for journal backend implementations.
func ValidateQuery(after int64, limit int) error {
	if after < 0 || limit < 1 || limit > 1000 {
		return ErrInvalidQuery
	}
	return nil
}

// Envelope identifies a committed transition without carrying credentials or
// policy documents. Sequence orders commits across the instance. At uses service
// time and can be equal across consecutive events.
type Envelope struct {
	Sequence  int64     `json:"sequence"`
	At        time.Time `json:"at"`
	Partition string    `json:"partition"`
	AccountID string    `json:"account_id"`
	Region    string    `json:"region"`
	RequestID string    `json:"request_id"`
	// ParentEventID links an asynchronous command to the accepted source event.
	ParentEventID string `json:"parent_event_id,omitempty"`
	ActorARN      string `json:"actor_arn"`
	ActorService  string `json:"actor_service,omitempty"`
}

// SessionIssued describes an STS credential publication. It deliberately omits
// access keys, session tokens, federation claims, tags and inline policies.
type SessionIssued struct {
	PrincipalARN string    `json:"principal_arn"`
	IssuerARN    string    `json:"issuer_arn"`
	SessionType  string    `json:"session_type"`
	Expiration   time.Time `json:"expiration"`
}

// AccessKeyAction identifies an accepted IAM access-key mutation. A status
// update is recorded even when the requested status was already in effect.
type AccessKeyAction string

const (
	AccessKeyCreated       AccessKeyAction = "created"
	AccessKeyStatusUpdated AccessKeyAction = "status_updated"
	AccessKeyDeleted       AccessKeyAction = "deleted"
)

// AccessKeyChanged identifies the affected key without its signing secret.
// Status is Active or Inactive for creation/update, and empty for deletion.
type AccessKeyChanged struct {
	Action       AccessKeyAction `json:"action"`
	AccessKeyID  string          `json:"access_key_id"`
	PrincipalARN string          `json:"principal_arn"`
	Status       string          `json:"status,omitempty"`
}

// AccountCreationChanged records an accepted Organizations provisioning intent
// or its terminal result. AccountID is populated only after success. Names,
// email addresses, tags and role policies remain in their owning repositories.
type AccountCreationChanged struct {
	OrganizationID    string `json:"organization_id"`
	CreationRequestID string `json:"creation_request_id"`
	AccountID         string `json:"account_id,omitempty"`
	State             string `json:"state"`
	FailureReason     string `json:"failure_reason,omitempty"`
}

// HandshakeChanged records a membership handshake transition without its
// email address, notes or staged tags. TargetAccountID is empty for an unresolved email.
type HandshakeChanged struct {
	Action          string `json:"action"`
	ParentID        string `json:"parent_id,omitempty"`
	OrganizationID  string `json:"organization_id"`
	HandshakeID     string `json:"handshake_id"`
	TargetAccountID string `json:"target_account_id,omitempty"`
	State           string `json:"state"`
}

// EffectivePolicyState describes a management-policy view's publication lifecycle.
type EffectivePolicyState string

const (
	EffectivePolicyScheduled EffectivePolicyState = "SCHEDULED"
	EffectivePolicyPublished EffectivePolicyState = "PUBLISHED"
	EffectivePolicyRemoved   EffectivePolicyState = "REMOVED"
)

// EffectivePolicyChanged records publication work without retaining policy
// documents. The envelope carries the originating request and transition time.
type EffectivePolicyChanged struct {
	OrganizationID  string               `json:"organization_id"`
	TargetAccountID string               `json:"target_account_id"`
	PolicyType      string               `json:"policy_type"`
	State           EffectivePolicyState `json:"state"`
}

// Event contains the envelope and its versioned, typed service payload.
type Event struct {
	Envelope
	KubernetesAuditObserved   *KubernetesAuditObserved  `json:"kubernetes_audit_observed_v1,omitempty"`
	APICallCompleted          *APICallCompleted         `json:"api_call_completed_v1,omitempty"`
	EventBridgeAccepted       EventBridgeAccepted       `json:"eventbridge_accepted_v1,omitzero"`
	LambdaInvocationAccepted  LambdaInvocationAccepted  `json:"lambda_invocation_accepted_v1,omitzero"`
	LambdaSourceBatchAccepted LambdaSourceBatchAccepted `json:"lambda_source_batch_accepted_v1,omitzero"`
	SQSMessageAccepted        SQSMessageAccepted        `json:"sqs_message_accepted_v1,omitzero"`
	LogsBatchAccepted         LogsBatchAccepted         `json:"logs_batch_accepted_v1,omitzero"`
	EffectivePolicyChanged    EffectivePolicyChanged    `json:"effective_policy_changed_v1,omitzero"`
	HandshakeChanged          HandshakeChanged          `json:"handshake_changed_v1,omitzero"`
	SessionIssued             SessionIssued             `json:"session_issued_v1,omitzero"`
	AccessKeyChanged          AccessKeyChanged          `json:"access_key_changed_v1,omitzero"`
	AccountCreationChanged    AccountCreationChanged    `json:"account_creation_changed_v1,omitzero"`
}

// Storage joins the resource transaction carried by ctx. Failed appends must
// abort that transaction. Reads expose committed events in ascending sequence;
// callbacks borrowing a transaction may also see their own staged events.
// Appends assign Sequence and leave caller values unchanged.
// Read returns at most limit entries strictly after after; callers supply a
// nonnegative cursor and a limit from 1 to 1000; invalid queries return ErrInvalidQuery. Implementations return detached values.
type Storage interface {
	// AppendKubernetesAuditObserved deduplicates by scope, cluster incarnation,
	// native audit ID and stage. False means a prior source admission committed.
	AppendKubernetesAuditObserved(context.Context, Envelope, KubernetesAuditObserved) (bool, error)
	AppendAPICallCompleted(ctx context.Context, envelope Envelope, call APICallCompleted) error
	LookupAPICalls(ctx context.Context, query APICallQuery) (APICallPage, error)
	// ReadAPICalls returns selected immutable outcomes in journal sequence order.
	// Missing IDs are omitted. Delivery references retain the corresponding log.
	ReadAPICalls(ctx context.Context, eventIDs []string) ([]Event, error)
	AppendEventBridgeAccepted(ctx context.Context, envelope Envelope, event EventBridgeAccepted) error
	AppendLambdaInvocationAccepted(ctx context.Context, envelope Envelope, event LambdaInvocationAccepted) error
	AppendLambdaSourceBatchAccepted(ctx context.Context, envelope Envelope, event LambdaSourceBatchAccepted) error
	AppendSQSMessageAccepted(ctx context.Context, envelope Envelope, event SQSMessageAccepted) error
	AppendLogsBatchAccepted(ctx context.Context, envelope Envelope, event LogsBatchAccepted) error
	AppendSessionIssued(ctx context.Context, envelope Envelope, session SessionIssued) error
	AppendAccessKeyChanged(ctx context.Context, envelope Envelope, change AccessKeyChanged) error
	AppendAccountCreationChanged(ctx context.Context, envelope Envelope, change AccountCreationChanged) error
	AppendHandshakeChanged(ctx context.Context, envelope Envelope, change HandshakeChanged) error
	AppendEffectivePolicyChanged(ctx context.Context, envelope Envelope, change EffectivePolicyChanged) error
	Read(ctx context.Context, after int64, limit int) ([]Event, error)
}
