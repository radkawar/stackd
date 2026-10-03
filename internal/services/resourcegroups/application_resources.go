package resourcegroups

import "context"

// ApplicationResource identifies the current owner incarnation. Tags are a
// detached snapshot for evaluation, never another authoritative tag store.
type ApplicationResource struct {
	ARN, Type, Name, Incarnation string
	Tags                         map[string]string
	// TaggingPending reflects actual owner work (for example a stack update).
	TaggingPending bool
}

// ApplicationResources supports only real, explicitly admitted owner types.
// Every method joins the context's coordinated storage transaction. Tag and
// Untag recheck the current incarnation and use ordinary current owner IAM.
type ApplicationResources interface {
	Resolve(context.Context, string) (ApplicationResource, bool, error)
	StackResources(context.Context, string) (ApplicationResource, []ApplicationResource, error)
	List(context.Context) ([]ApplicationResource, error)
	Tag(context.Context, ApplicationResource, map[string]string) error
	Untag(context.Context, ApplicationResource, []string) error
}
