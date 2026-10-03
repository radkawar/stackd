// Package policy parses, evaluates and composes IAM permission policies without
// HTTP, storage or clock dependencies. Authorize combines identity, boundary,
// session, resource and Organizations controls and returns a structured trace.
// Callers authenticate principals, select current applicable policy snapshots,
// construct trusted context and check every required action and resource.
//
// Evaluate and EvaluateResource expose the underlying matchers. The detailed
// and simulation APIs retain AWS simulation's distinct diagnostic contract;
// their missing-context summaries are not enforcement denial explanations.
//
// Parse validates the supported evaluation language. Storage APIs that accept
// other policy kinds or unsupported features must use separate validation.
package policy

import "errors"

var (
	// ErrInvalidPolicy identifies malformed identity policy documents.
	ErrInvalidPolicy = errors.New("invalid IAM identity policy")
	// ErrUnsupported identifies policy features that cannot be evaluated yet.
	ErrUnsupported = errors.New("unsupported IAM policy feature")
	// ErrInvalidRequest identifies invalid or ambiguous authorization input.
	ErrInvalidRequest = errors.New("invalid IAM policy request")
)

// Decision is the outcome of identity-policy evaluation. Its zero value denies
// access. Callers must handle any evaluation error before using the decision.
type Decision string

const (
	ImplicitDeny Decision = "implicitDeny"
	ExplicitDeny Decision = "explicitDeny"
	Allow        Decision = "allowed"
)

// Request describes one action on one resource. Action must be a concrete AWS
// action, such as s3:GetObject. Resource is an ARN, or "*" for operations that do
// not support resource-level permissions. The caller must validate that the
// action and resource are applicable to each other.
//
// Context keys are case-insensitive. Missing keys and nil slices represent
// missing values; nonnil empty slices represent present empty sets. An empty
// string remains a present value. Multivalued keys require a set operator.
// Case-colliding map keys are rejected. The caller must not mutate request maps
// or slices during evaluation.
type Request struct {
	Action string
	// ActionAliases match equivalent names in ordinary IAM policy statements.
	// Authorize excludes these aliases from Organizations SCP/RCP evaluation.
	// Only a service's fixed operation contract may supply them.
	ActionAliases []string
	// AdditionalDenyActions checks these actions in Deny statements as well as
	// Action. They never contribute Allow statements. A service uses this when
	// a broader permission covers an operation whose explicit denials still
	// apply, such as S3 ReplicateObject covering ReplicateTags.
	AdditionalDenyActions []string
	Resource              string
	Context               map[string][]string
	// ContextTypes declares string, numeric, boolean, date, ip or binary types,
	// optionally suffixed with List. A List key remains multivalued with one
	// value. Callers supply authoritative types for the context they construct;
	// undeclared keys infer cardinality from the values. Ordinary evaluation
	// checks scalar cardinality but does not coerce values by their declared
	// type. The simulation caller also normalizes keys and typed values before
	// evaluation, following IAM's distinct input-conversion contract.
	ContextTypes map[string]string
}

// Document is an immutable, parsed identity policy, safe for concurrent use.
// Construct documents with Parse; the zero value grants no permissions.
type Document struct {
	statements     []statement
	resourcePolicy bool
}

type statement struct {
	start            Position
	end              Position
	sid              string
	effect           Decision
	actions          []string
	notAction        bool
	resources        []valueTemplate
	resourcePatterns []string
	notResource      bool
	conditions       []condition
	principals       []principalPattern
	notPrincipal     bool
}
