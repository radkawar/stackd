package policy

import "fmt"

// ParseSimulation accepts the inert top-level Id permitted by IAM's simulation
// API for identity, boundary and organization policies. It otherwise compiles
// the same policy language and rejects resource-policy principal selectors.
// Invalid IP literals remain available for the simulator's comparison rules.
// Storage and ordinary identity-policy validation continue to use Parse.
func ParseSimulation(data []byte) (*Document, error) {
	return parseDocument(data, simulationDocument)
}

// ParseResourceSimulation accepts principal selectors and applies the same IP
// literal rules as ParseSimulation. Actual resource-policy writes continue to
// use ParseResource and reject invalid literals.
func ParseResourceSimulation(data []byte) (*Document, error) {
	return parseDocument(data, simulationResourceDocument)
}

// EvaluateSimulationDetailed evaluates the hypothetical action spelling
// accepted by IAM simulation, including unknown names and literal wildcard
// characters. Unlike EvaluateDetailed it does not require a concrete AWS action.
// The IAM caller validates the complete simulation request before evaluation,
// including action/resource compatibility, and normalizes Context and
// ContextTypes: keys are lowercase and typed values have canonical spelling.
// This evaluator consumes that normalized request directly. Its policy matcher
// is shared with authorization; this API must not authorize actual operations.
func EvaluateSimulationDetailed(documents []*Document, request Request) (Evaluation, error) {
	trace := evaluationTrace{}
	context := evaluationContext{values: request.Context, types: request.ContextTypes}
	decision, err := evaluate(documents, request, context, &trace, true)
	return Evaluation{Decision: decision, MatchedStatements: trace.matches, MissingContextValues: missingContextValues(documents, context, decision)}, err
}

// EvaluateResourceSimulationDetailed is the resource-policy counterpart of
// EvaluateSimulationDetailed. Principal selection is identical to enforcement.
func EvaluateResourceSimulationDetailed(document *Document, request Request, principal Principal) (ResourceEvaluation, error) {
	if document == nil || !document.resourcePolicy {
		return ResourceEvaluation{ResourceDecision: ResourceDecision{Decision: ImplicitDeny}}, fmt.Errorf("%w: resource evaluation requires a resource policy document", ErrInvalidPolicy)
	}
	trace := evaluationTrace{}
	context := evaluationContext{values: request.Context, types: request.ContextTypes}
	decision, err := evaluateResource(document, request, context, principal, &trace, true)
	return ResourceEvaluation{ResourceDecision: decision, MatchedStatements: trace.matches, MissingContextValues: missingContextValues([]*Document{document}, context, decision.Decision)}, err
}
