package cloudformation

import "context"

// Properties contains resolved customer template properties. It is not an
// alternate resource store: the invoked service remains authoritative.
type Properties map[string]any

// ResourceRequest is the version-one consumer boundary for built-in resource
// handlers. Token is stable across controller recovery and names one physical
// incarnation; PhysicalID identifies a previously completed owner command.
type ResourceRequest struct {
	StackID, StackName, LogicalID, Type, PhysicalID, Token string
	// OperationToken identifies this deployment independently of the resource's
	// physical-incarnation Token, for idempotent asynchronous owner updates.
	OperationToken       string
	Scope                Scope
	Properties, Previous Properties
	Tags                 map[string]string
	// CloudControl selects direct resource operations. Owner authorization still
	// applies; stack-incarnation ownership is not required for reads or mutations.
	CloudControl bool
	// DeletionPolicy is the effective policy for the current deletion. Empty
	// selects the resource's AWS default; rollback and replacement default to
	// Delete rather than inheriting a stack-deletion snapshot preference.
	DeletionPolicy string
}

type ResourceResult struct {
	PhysicalID, Ref string
	Attributes      map[string]any
}

// ResourcePendingError means an owner has not yet admitted the command because
// a prior asynchronous transition is still active. Only this explicit signal
// retries admission; ordinary modeled failures still trigger failure/rollback.
type ResourcePendingError struct {
	Reason string
}

func (e *ResourcePendingError) Error() string { return e.Reason }

// ResourceHandler delegates effects to the existing typed service owner under
// the supplied current caller or assumed service-role context. Create must be
// recoverable with the same Token without adopting an unrelated resource.
// A failure after native admission must still return the admitted PhysicalID so
// rollback can remove partial resources rather than forgetting owner effects.
type ResourceHandler interface {
	Validate(Properties) error
	Replacement(Properties, Properties) (bool, error)
	Create(context.Context, ResourceRequest) (ResourceResult, error)
	Update(context.Context, ResourceRequest) (ResourceResult, error)
	Delete(context.Context, ResourceRequest) error
}

// ResourceUpdateValidator admits resolved updates whose writable desired state
// intentionally omits create-required, write-only properties that cannot be
// recovered from an owner Read. Create and replacement still use Validate.
type ResourceUpdateValidator interface {
	ValidateUpdate(Properties, Properties) error
}

// ResourceCreationRecoverer observes only this exact physical-incarnation Token
// after a Create failed or its result commit was interrupted. It must not adopt
// another incarnation, even when its requested properties or name match.
// A modeled NotFound certifies that this incarnation has no admitted native
// resource and that partial ownership claims have been cleaned up safely.
// Dependency absence, authorization failures and unavailable observations are
// ordinary errors, not proof that this incarnation was never admitted.
type ResourceCreationRecoverer interface {
	RecoverCreation(context.Context, ResourceRequest) (ResourceResult, error)
}

// ScopedResourceReplacement resolves relative resource names before deciding
// whether an update changes physical identity. Other handlers need properties only.
type ScopedResourceReplacement interface {
	ReplacementInScope(Scope, Properties, Properties) (bool, error)
}

// ResourceContextualReplacementPlanner resolves owner-dependent replacement
// under current caller authority. The controller invokes it outside storage
// transactions with the existing physical identity and desired properties.
type ResourceContextualReplacementPlanner interface {
	ReplacementForResource(context.Context, ResourceRequest) (bool, error)
}

// RequiresReplacement resolves execution-time identity in the caller's scope,
// independently of the potentially Conditional public change-set plan.
func RequiresReplacement(h ResourceHandler, scope Scope, before, after Properties) (bool, error) {
	if scoped, ok := h.(ScopedResourceReplacement); ok {
		return scoped.ReplacementInScope(scope, before, after)
	}
	return h.Replacement(before, after)
}

// ResourceReplacementPlanner reports a public change-set decision ("True",
// "False" or "Conditional") when it differs from the execution-time identity
// decision. Conditional plans must still resolve replacement before execution.
type ResourceReplacementPlanner interface {
	ReplacementPlan(Properties, Properties) (string, error)
}

func resourceReplacementPlan(h ResourceHandler, scope Scope, before, after Properties) (string, error) {
	if planner, ok := h.(ResourceReplacementPlanner); ok {
		return planner.ReplacementPlan(before, after)
	}
	replace, err := RequiresReplacement(h, scope, before, after)
	if err != nil {
		return "", err
	}
	if replace {
		return "True", nil
	}
	return "False", nil
}

// deleteBeforeCreate follows the official resource schema's replacement
// strategy, including type changes away from an exclusive native association.
func deleteBeforeCreate(step StepRecord) bool {
	return step.Action == "REPLACE" && (resourceSchemas[step.Before.Type].ReplacementStrategy == "delete_then_create" || resourceSchemas[step.After.Type].ReplacementStrategy == "delete_then_create")
}

// ResourceDescription is an authoritative projection obtained from the service
// owner, not a retained deployment snapshot.
type ResourceDescription struct {
	Identifier string
	Properties Properties
}

// ResourceReader supplies Cloud Control's live reads and discovery using the
// same physical identifiers accepted by the resource handler.
type ResourceReader interface {
	Read(context.Context, ResourceRequest) (Properties, error)
	List(context.Context, ResourceRequest) ([]ResourceDescription, error)
}

// ResourceStabilizer observes asynchronous service-owned effects without holding
// the shared scheduler while another owner's lifecycle job must run.
type ResourceStabilizer interface {
	Stabilize(context.Context, ResourceRequest) (bool, error)
}

// ResourceResultReader refreshes identifiers and attributes after asynchronous
// owner effects stabilize. The physical identity must remain the admitted
// resource incarnation; attributes such as a DynamoDB stream ARN may change.
type ResourceResultReader interface {
	Result(context.Context, ResourceRequest) (ResourceResult, error)
}

// ResourceDeletionPolicyValidator admits resource-specific deletion effects.
// Snapshot is rejected unless the handler implements and validates that effect.
type ResourceDeletionPolicyValidator interface {
	ValidateDeletionPolicy(string) error
}

type ResourceDeletionStabilizer interface {
	StabilizeDeletion(context.Context, ResourceRequest) (bool, error)
}

// ExecutionRoles resolves fresh role authority for every deployment command.
type ExecutionRoles interface {
	Validate(context.Context, string, string) error
	Context(context.Context, string, string) (context.Context, error)
}
