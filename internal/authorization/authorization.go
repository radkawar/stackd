// Package authorization composes IAM identity, boundary, resource and Organizations
// control policies for authenticated requests. Service providers identify the
// required action and resource; transport decoding is outside this package.
package authorization

import (
	"context"
	"net/http"
	"time"

	"stackd/clock"
	"stackd/iam/policy"
	"stackd/internal/awswire"
)

// Request describes a single required permission. Context contains trusted
// service-specific values, such as resource tags and KMS encryption context.
// Callers keep the snapshot stable; implementations must not modify its maps or
// policy bindings. RequireResourcePolicy models services such as KMS where
// identity permissions alone cannot grant access to a resource.
type Request struct {
	Action      string
	ResourceARN string
	// AdditionalDenyActions retains explicit denials for operations covered by
	// Action without requiring separate grants for those narrower operations.
	AdditionalDenyActions []string
	// PolicyActionAliases are service-owned equivalent IAM action names. They
	// participate in identity, boundary, session and resource policies, never
	// Organizations controls. The requested Action remains the audit/context
	// authority. Callers must select aliases from a fixed service contract.
	PolicyActionAliases []string
	// EvaluationTime is the trusted instant captured by the service for this
	// authorization decision. Nil uses the evaluator clock.
	EvaluationTime *time.Time
	// ResourceAccountID is the service-resolved owner when the ARN omits the
	// account, uses an AWS-owned alias, or the operation selects *. It cannot
	// override a numeric ARN owner.
	ResourceAccountID string
	// ResourceAccountGrant carries current service-owned account access. It
	// supplies resource-side permission without bypassing any explicit denial
	// or the caller's identity, boundary, session and Organizations restrictions.
	ResourceAccountGrant bool
	// ResourcePublicGrant carries an effective public ACL permission for this
	// action/resource and the caller's session. Same-account implicit ceilings
	// do not restrict it. Explicit denials and Organizations controls still apply;
	// signed cross-account callers also need identity permission.
	ResourcePublicGrant bool
	// ResourcePolicyDenyOnly retains resource-policy denials but ignores their
	// grants, as for a bucket policy applied to a foreign-owned S3 object.
	ResourcePolicyDenyOnly bool
	// ResourcePolicies are the applicable resource grants and immutable principal
	// bindings. They share one decision: any matching explicit denial wins.
	ResourcePolicies      []BoundPolicy
	RequireResourcePolicy bool
	// ResourceControlExempt is set only from service-owned state: an AWS-managed
	// KMS key or a service-linked role's trust. It never bypasses other policies.
	ResourceControlExempt bool
	Grants                policy.GrantPermissions
	Context               map[string][]string
	// ContextTypes supplies operation-specific types when the service-wide IAM
	// catalog combines scalar and multivalued uses of the same condition key.
	ContextTypes map[string]string
	// ObserveDecision receives the completed policy result once, including
	// denials, before translation to a wire error. It is not called when
	// authorization fails before or during policy evaluation. The callback
	// must not perform external effects; the evaluator retains no callback
	// or request state.
	ObserveDecision func(policy.AuthorizationResult)
}

// Authorizer is consumed by services before protected state transitions.
// Calls can run inside a resource transaction: implementations must use ctx for
// related repository reads and must not perform external effects.
type Authorizer interface {
	Authorize(context.Context, Request) *awswire.Error
}

// PolicySet is an immutable snapshot of the caller's effective IAM attachments.
// An empty boundary with HasBoundary set denies permissions; it does not mean
// that the boundary is absent. PrincipalTags supplies authenticated IAM tags.
type PolicySet struct {
	Identity       []policy.Policy
	Boundary       []policy.Policy
	HasBoundary    bool
	ManagedSession []policy.Policy
	PrincipalTags  map[string]string
	// ServiceLinkedRole is supplied only by the current IAM role record after
	// matching its immutable identity. Service-linked roles are exempt from
	// Organizations SCPs and RCPs; names, paths and request context cannot confer this.
	ServiceLinkedRole bool
}

// IdentitySource loads current policies for the verified request principal.
// Missing or deleted principals must return an error, even if a resource policy
// would otherwise grant access to their old ARN.
type IdentitySource interface {
	IdentityPolicies(context.Context) (PolicySet, error)
}

// ControlSource returns the caller account's applicable SCP hierarchy. An empty
// hierarchy means no SCP restriction, for example for the management account.
type ControlSource interface {
	ServiceControlPolicies(context.Context) ([]policy.PolicyLevel, error)
}

// ResourceControlSource resolves the resource owner's hierarchy, independently
// of the caller's SCP hierarchy. The request context supplies the partition.
type ResourceControlSource interface {
	ResourceControlPolicies(context.Context, string) (ResourceControlSet, error)
}

// ResourceControlSet keeps resource-owner ancestry and its RCP hierarchy in
// one snapshot. Organization context remains present when RCPs are disabled.
type ResourceControlSet struct {
	Levels                           []policy.PolicyLevel
	OrganizationID, OrganizationPath string
}

// OrganizationSource supplies the verified caller's organization and ancestry.
// Empty strings mean the account does not belong to an organization. The path
// contains the organization, root and OUs, with a trailing slash, not the account.
type OrganizationSource interface {
	PrincipalOrganization(context.Context) (id, path string, err error)
}

// Evaluator combines policy decisions without owning identity or resource state.
type Evaluator struct {
	// TODO: Comeback complete action/resource/condition conformance and dependent-action denial traces, keeping enforcement and simulation contracts distinct.
	identity IdentitySource
	controls ControlSource
	clock    clock.Clock
}

// New constructs a policy evaluator. A nil identity source permits only verified
// account roots; a nil controls source means no Organizations SCPs are configured.
func New(identity IdentitySource, controls ControlSource) *Evaluator {
	return NewWithClock(identity, controls, clock.Real{})
}

// NewWithClock uses service time for date conditions and MFA authentication age.
func NewWithClock(identity IdentitySource, controls ControlSource, source clock.Clock) *Evaluator {
	if source == nil {
		source = clock.Real{}
	}
	return &Evaluator{identity: identity, controls: controls, clock: source}
}

func denied(message string) *awswire.Error {
	return &awswire.Error{Code: "AccessDenied", Message: message, StatusCode: http.StatusForbidden}
}
