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
	Scope                                                  Scope
	Properties, Previous                                   Properties
	Tags                                                   map[string]string
	// CloudControl selects direct resource operations. Owner authorization still
	// applies; stack-incarnation ownership is not required for reads or mutations.
	CloudControl bool
}

type ResourceResult struct {
	PhysicalID, Ref string
	Attributes      map[string]any
}

// ResourceHandler delegates effects to the existing typed service owner under
// the supplied current caller or assumed service-role context. Create must be
// recoverable with the same Token without adopting an unrelated resource.
type ResourceHandler interface {
	Validate(Properties) error
	Replacement(Properties, Properties) (bool, error)
	Create(context.Context, ResourceRequest) (ResourceResult, error)
	Update(context.Context, ResourceRequest) (ResourceResult, error)
	Delete(context.Context, ResourceRequest) error
}

// ScopedResourceReplacement resolves relative resource names before deciding
// whether an update changes physical identity. Other handlers need properties only.
type ScopedResourceReplacement interface {
	ReplacementInScope(Scope, Properties, Properties) (bool, error)
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

type ResourceDeletionStabilizer interface {
	StabilizeDeletion(context.Context, ResourceRequest) (bool, error)
}

// ExecutionRoles resolves fresh role authority for every deployment command.
type ExecutionRoles interface {
	Validate(context.Context, string, string) error
	Context(context.Context, string, string) (context.Context, error)
}
