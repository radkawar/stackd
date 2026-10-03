package policy

import (
	"fmt"
	"strings"
)

// Evaluate returns the combined identity-policy decision for a single action
// and resource. Explicit denies override allows regardless of document order.
// Invalid request structure or document kinds return ImplicitDeny and an error.
// Condition conversion and malformed ARN operands follow AWS matching rules.
func Evaluate(documents []*Document, request Request) (Decision, error) {
	context, err := requestContext(request)
	if err != nil {
		return ImplicitDeny, err
	}
	return evaluate(documents, request, context, nil, false)
}

func evaluate(documents []*Document, request Request, context evaluationContext, trace *evaluationTrace, simulation bool) (Decision, error) {
	decision := ImplicitDeny
	for documentIndex, doc := range documents {
		if doc == nil || doc.resourcePolicy {
			if decision == ExplicitDeny {
				continue
			}
			return ImplicitDeny, fmt.Errorf("%w: identity evaluation requires identity policy documents", ErrInvalidPolicy)
		}
		for statementIndex, st := range doc.statements {
			entry := trace.begin(documentIndex, statementIndex, st)
			if !matchesActionResource(st, request, context, entry) {
				continue
			}
			if !matchesRequestConditions(st, context, simulation, entry) {
				continue
			}
			entry.outcome(StatementMatched)
			trace.match(documentIndex, statementIndex, st)
			if st.effect == ExplicitDeny {
				if trace == nil {
					return ExplicitDeny, nil
				}
				decision = ExplicitDeny
			} else if decision != ExplicitDeny {
				decision = Allow
			}
		}
	}
	if decision == ExplicitDeny {
		return decision, nil
	}
	return decision, nil
}

func matchesActionResource(st statement, request Request, context evaluationContext, trace *statementTrace) bool {
	trace.outcome(ActionMismatch)
	actionMatched := matchesAny(st.actions, strings.ToLower(request.Action), true, false)
	if !actionMatched {
		for _, action := range request.ActionAliases {
			if matchesAny(st.actions, strings.ToLower(action), true, false) {
				actionMatched = true
				break
			}
		}
	}
	actionMatched = actionMatched != st.notAction
	if !actionMatched && st.effect == ExplicitDeny {
		for _, action := range request.AdditionalDenyActions {
			if matchesAny(st.actions, strings.ToLower(action), true, false) != st.notAction {
				actionMatched = true
				break
			}
		}
	}
	if !actionMatched {
		return false
	}
	trace.outcome(ResourceMismatch)
	trace.resources(st.resources, context.values)
	matched := false
	for _, resource := range st.resources {
		_, tokens, present := resource.expand(context)
		if present && matchPattern(tokens, request.Resource, true) {
			matched = true
		}
	}
	return matched != st.notResource
}

func matchesAny(patterns []string, value string, foldCase, resource bool) bool {
	for _, pattern := range patterns {
		if foldCase {
			pattern = strings.ToLower(pattern)
		}
		if wildcardMatch(pattern, value, resource) {
			return true
		}
	}
	return false
}
