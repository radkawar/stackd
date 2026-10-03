package policy

import "slices"

// MatchOutcome identifies the stage that selected or rejected a statement.
type MatchOutcome string

const (
	StatementMatched   MatchOutcome = "matched"
	ActionMismatch     MatchOutcome = "actionMismatch"
	ResourceMismatch   MatchOutcome = "resourceMismatch"
	PrincipalMismatch  MatchOutcome = "principalMismatch"
	ConditionsMismatch MatchOutcome = "conditionsMismatch"
)

// StatementEvaluation records enforcement's actual matching path. Conditions
// contains only comparisons reached before short-circuiting. MissingVariables
// records absent Resource variables, not unrelated statements' context. Absence
// alone is not a failure: negation, Null and IfExists can permit missing input.
// PrincipalBinding records the resource principal match before NotPrincipal is
// applied. BoundaryDeny identifies its special permissions-boundary deny rule.
type StatementEvaluation struct {
	StatementIndex   int
	SID              string
	Effect           Decision
	Start, End       Position
	Outcome          MatchOutcome
	MissingVariables []string
	PrincipalBinding PrincipalBinding
	NotPrincipal     bool
	BoundaryDeny     bool
	Conditions       []ConditionEvaluation
}

// PrincipalBinding distinguishes direct principal grants from account delegation
// before the enclosing statement's NotPrincipal and condition rules are applied.
type PrincipalBinding struct {
	Direct, Delegated, SessionDirect bool
}

// ConditionEvaluation reports one comparison without retaining supplied values.
// MissingVariables identifies absent variables in the policy comparison value.
// Missing reports an absent context key, while Matched is the actual operator
// result (so an absent key may still match). Failed indicates evaluation error.
type ConditionEvaluation struct {
	Operator         string
	Key              string
	Missing          bool
	MissingVariables []string
	Matched          bool
	Failed           bool
}

type statementTrace struct {
	document int
	StatementEvaluation
}

func (t *evaluationTrace) begin(documentIndex, statementIndex int, st statement) *statementTrace {
	if t == nil || !t.explain {
		return nil
	}
	entry := &statementTrace{document: documentIndex, StatementEvaluation: StatementEvaluation{
		StatementIndex: statementIndex, SID: st.sid, Effect: st.effect, Start: st.start, End: st.end,
	}}
	t.statements = append(t.statements, entry)
	return entry
}

func (t *statementTrace) outcome(outcome MatchOutcome) {
	if t != nil {
		t.Outcome = outcome
	}
}

func (t *statementTrace) resources(resources []valueTemplate, context map[string][]string) {
	if t == nil {
		return
	}
	missing := missingContext{}
	for _, resource := range resources {
		missing.template(resource, context)
	}
	t.MissingVariables = sortedMissing(missing)
}

func (t *statementTrace) condition(c condition, context map[string][]string, matched bool, err error) {
	if t == nil {
		return
	}
	missing := missingContext{}
	for _, value := range c.values {
		if value.template != nil {
			missing.template(*value.template, context)
		}
	}
	t.Conditions = append(t.Conditions, ConditionEvaluation{
		Operator: c.name, Key: c.sourceKey, Missing: len(context[c.key]) == 0,
		MissingVariables: sortedMissing(missing), Matched: matched, Failed: err != nil,
	})
}

func sortedMissing(missing missingContext) []string {
	keys := make([]string, 0, len(missing))
	for key := range missing {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func (t *evaluationTrace) policies(policies []PolicyEvaluation) {
	for _, entry := range t.statements {
		p := &policies[entry.document]
		p.Statements = append(p.Statements, entry.StatementEvaluation)
		if entry.Outcome == StatementMatched && (p.Decision != ExplicitDeny || entry.Effect == ExplicitDeny) {
			p.Decision = entry.Effect
		}
		p.Failed = p.Failed || slices.ContainsFunc(entry.Conditions, func(c ConditionEvaluation) bool { return c.Failed })
	}
}
