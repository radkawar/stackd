package policy

import (
	"fmt"
	"slices"
	"strings"
)

// Position identifies a location in the original bytes passed to Parse or
// ParseResource. Line and Column are one-based. Statement starts follow IAM's
// delimiter positions (after the array opener or preceding statement), and
// ends point immediately after the statement's closing brace.
type Position struct {
	Line   int
	Column int
}

// StatementMatch identifies a fully matching statement. DocumentIndex and
// StatementIndex are zero-based indexes in the supplied documents and their
// original Statement order. Source policy names and types belong to callers.
type StatementMatch struct {
	DocumentIndex  int
	StatementIndex int
	Effect         Decision
	Start          Position
	End            Position
}

// Evaluation explains a single action/resource evaluation. MatchedStatements
// contains every fully matching allow and deny, in document/statement order;
// callers can select the statements contributing to their composed decision.
// MissingContextValues is sorted and deduplicated. Returned slices are owned by
// the caller. For an implicit denial it includes missing input from the supplied
// documents, including statements with other actions/resources, as IAM's policy
// simulator does. Allowed and explicitly denied evaluations report no missing
// values. As with Evaluate, an error must never be treated as permission.
type Evaluation struct {
	Decision             Decision
	MatchedStatements    []StatementMatch
	MissingContextValues []string
}

// ResourceEvaluation includes the direct/account/session grant distinctions of
// EvaluateResource, with the same diagnostics as Evaluation. DocumentIndex is
// zero because this API takes one resource policy.
type ResourceEvaluation struct {
	ResourceDecision
	MatchedStatements    []StatementMatch
	MissingContextValues []string
}

// ResourcePatterns returns a detached copy of every original Resource or
// NotResource pattern, preserving document order, variables and spelling.
// Callers can apply API-specific validation without reparsing the document.
func (d *Document) ResourcePatterns() []string {
	patterns := []string{}
	if d != nil {
		for _, statement := range d.statements {
			patterns = append(patterns, statement.resourcePatterns...)
		}
	}
	return patterns
}

// MissingSimulationContextValues reports missing input across the supplied
// policy layers, independent of each layer's decision. explicitContext contains
// only context supplied by the simulation caller, excluding automatically
// populated defaults. The service calls this when its final composed decision
// is implicitDeny. Keys are case-insensitive for presence and retain their
// original policy spelling in the sorted, detached result. This is diagnostic
// introspection; it does not validate a request or grant permissions.
func MissingSimulationContextValues(documents []*Document, explicitContext map[string][]string) []string {
	present := make(map[string][]string, len(explicitContext))
	for key, values := range explicitContext {
		if len(values) != 0 {
			present[strings.ToLower(key)] = values
		}
	}
	return missingContextValues(documents, evaluationContext{values: present}, ImplicitDeny)
}

// EvaluateDetailed uses the same matcher as Evaluate and additionally collects
// statement locations and missing context diagnostics. It scans
// past explicit denies to retain all matching statements; explicit deny still
// takes precedence over matching allows. Malformed ARN policy operands retain
// their statement-effect behavior.
func EvaluateDetailed(documents []*Document, request Request) (Evaluation, error) {
	trace := evaluationTrace{}
	context, err := requestContext(request)
	if err != nil {
		return Evaluation{Decision: ImplicitDeny}, err
	}
	decision, err := evaluate(documents, request, context, &trace, false)
	return Evaluation{Decision: decision, MatchedStatements: trace.matches, MissingContextValues: missingContextValues(documents, context, decision)}, err
}

// EvaluateResourceDetailed is the diagnostic counterpart of EvaluateResource.
// It retains principal selection and the NotPrincipal/boundary deny rule.
func EvaluateResourceDetailed(document *Document, request Request, principal Principal) (ResourceEvaluation, error) {
	if document == nil || !document.resourcePolicy {
		return ResourceEvaluation{ResourceDecision: ResourceDecision{Decision: ImplicitDeny}}, fmt.Errorf("%w: resource evaluation requires a resource policy document", ErrInvalidPolicy)
	}
	trace := evaluationTrace{}
	context, err := requestContext(request)
	if err != nil {
		return ResourceEvaluation{ResourceDecision: ResourceDecision{Decision: ImplicitDeny}}, err
	}
	decision, err := evaluateResource(document, request, context, principal, &trace, false)
	return ResourceEvaluation{ResourceDecision: decision, MatchedStatements: trace.matches, MissingContextValues: missingContextValues([]*Document{document}, context, decision.Decision)}, err
}

type evaluationTrace struct {
	matches    []StatementMatch
	explain    bool
	statements []*statementTrace
}

func (t *evaluationTrace) match(documentIndex, statementIndex int, st statement) {
	if t != nil {
		t.matches = append(t.matches, StatementMatch{DocumentIndex: documentIndex, StatementIndex: statementIndex, Effect: st.effect, Start: st.start, End: st.end})
	}
}

func missingContextValues(documents []*Document, context evaluationContext, decision Decision) []string {
	keys := []string{}
	if decision != ImplicitDeny {
		return keys
	}
	missing := missingContext{}
	for _, document := range documents {
		if document == nil {
			continue
		}
		for _, statement := range document.statements {
			for _, resource := range statement.resources {
				missing.template(resource, context.values)
			}
			missing.conditions(statement.conditions, context)
		}
	}
	for key := range missing {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

type missingContext map[string]struct{}

func (m missingContext) template(template valueTemplate, context map[string][]string) {
	for _, part := range template.parts {
		if part.key != "" && len(context[part.key]) == 0 {
			m[part.sourceKey] = struct{}{}
		}
	}
}

func (m missingContext) conditions(conditions []condition, context evaluationContext) {
	for _, condition := range conditions {
		if !context.nonNull(condition.key) {
			m[condition.sourceKey] = struct{}{}
		}
		for _, value := range condition.values {
			if value.template != nil {
				m.template(*value.template, context.values)
			}
		}
	}
}
