// Package simcatalog exposes generated IAM simulator presentation and action
// grouping metadata. It describes hypothetical evaluation, not authorization.
package simcatalog

// Action records the simulator's aggregate resource template and whether the
// action participates in resource-aware evaluation. Names absent from a capture
// are not evidence that the corresponding AWS service operation is implemented.
type Action struct {
	AggregateTemplate string
	// DefaultResourceTemplate preserves literal AWS placeholders. Only the
	// generated ${AuthenticatedAccount} token represents the API caller account.
	DefaultResourceTemplate string
	HasAggregateTemplate    bool
	ResourceAware           bool
}

// LookupAction uses the exact simulator spelling. Simulator recognition is
// separate from case-insensitive policy Action matching.
func LookupAction(name string) (Action, bool) {
	action, exists := generatedActions[name]
	return action, exists
}
