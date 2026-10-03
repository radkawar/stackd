package organizations

import (
	"context"
	"time"
)

// These record aliases expose typed Organizations resources to storage
// implementations without importing transport-specific SDK models.
type OrganizationDetails = organization
type RootRecord = root
type AccountRecord = account
type UnitRecord = organizationalUnit

// AccountCreationRecord retains the accepted provisioning intent and its result.
// AccountID is reserved at admission; only SUCCEEDED exposes it to API callers.
// CompletedAt is meaningful for terminal states, including the zero epoch.
type AccountCreationRecord struct {
	ID, AccountID, AccountName, Email, RoleName string
	State, FailureReason                        string
	RequestedAt, Due, CompletedAt               time.Time
	Tags                                        map[string]string
	// Origin survives worker recovery without retaining credentials. Older
	// stored jobs have no request origin; recovery must not invent one.
	RequestID, RequestRegion, ActorARN string
}
type PolicyRecord = policy
type PolicyTypeRecord = policyType
type PolicySummaryRecord = policySummary

type ParentRecord struct{ ChildID, ParentID string }
type PolicyAttachment struct{ TargetID, PolicyID string }
type ResourceTagRecord struct{ ResourceID, Key, Value string }
type ServiceAccessRecord struct {
	Principal string
	Enabled   float64
}

// ResourcePolicyRecord is the organization's singleton delegation policy.
// An empty ID denotes absence; tags use the ordinary resource-tag records.
type ResourcePolicyRecord struct{ ID, ARN, Content string }

type DelegationRecord struct {
	AccountID, Principal string
	Enabled              float64
}

// OrganizationRecord is a typed aggregate with explicit resource relationships.
// A relational backend can store each resource family in its own SQLC tables.
type OrganizationRecord struct {
	Organization   OrganizationDetails
	ResourcePolicy ResourcePolicyRecord
	Root           RootRecord
	RootAccess     RootAccessFeatures
	Accounts       []AccountRecord
	Units          []UnitRecord
	Parents        []ParentRecord
	Creations      []AccountCreationRecord
	Policies       []PolicyRecord
	// Attachments preserve attachment order within each target.
	Attachments       []PolicyAttachment
	EffectivePolicies []EffectivePolicyRecord
	Tags              []ResourceTagRecord
	Services          []ServiceAccessRecord
	Delegations       []DelegationRecord
}

// PartitionRecord contains the organizations and account registry of one AWS
// partition. Removed accounts remain registered independently of membership.
type PartitionRecord struct {
	Organizations   []OrganizationRecord
	Handshakes      []HandshakeRecord
	Accounts        []AccountRecord
	AccountSequence uint64
}

// Storage atomically compares and replaces typed partition state. Load returns
// independent records and a monotonically increasing revision. CompareAndSwap
// changes nothing when the revision differs or an error occurs. This lets
// service authorization run without holding storage locks or SQL transactions.
// When ctx carries a related IAM transaction, both methods must join it:
// successful writes remain staged until that transaction commits, and roll back
// with its callback failure or cancellation.
// A nonnil commit callback runs only after a matching revision has staged its
// state. It borrows that transaction through its context and must not perform
// external effects. Its failure or cancellation rolls back state and effects.
type Storage interface {
	// Partitions enumerates retained state for service-job recovery.
	Partitions(context.Context) ([]string, error)
	Load(context.Context, string) (PartitionRecord, uint64, error)
	CompareAndSwap(context.Context, string, uint64, PartitionRecord, func(context.Context) error) (bool, error)
}
