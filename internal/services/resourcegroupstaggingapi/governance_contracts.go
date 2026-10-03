package resourcegroupstaggingapi

import "context"

// Target identifies an Organizations account, organizational unit or root.
// ParentID describes the committed organization tree, not a cached copy.
type Target struct{ ID, Type, ParentID string }
type Organization struct {
	ID, ManagementAccountID string
	Targets                 []Target
}

// Governance resolves trusted organization-wide scope only after admitting the
// current caller as the organization's management account with tag-policy
// integration enabled. Regions reads each account's actual enabled Regions.
type Governance interface {
	Organization(context.Context) (Organization, error)
	Regions(context.Context, string) ([]string, error)
	// RequiredResourceTypes expands only documented required-reporting support.
	RequiredResourceTypes(string) ([]string, error)
	// CloudFormationTypes resolves policy resource types, never guesses casing.
	CloudFormationTypes(string) ([]string, error)
}

// Reports performs native S3 destination admission and forwards the accepted
// caller through tagpolicies.tag.amazonaws.com. It retains caller/session and
// bucket/KMS authority, including aws:CalledViaLast conditions and encryption.
type Reports interface {
	ValidateDestination(context.Context, string, string) error
	Deliver(context.Context, string, string, string, []byte) error
}
