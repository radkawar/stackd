package policy

import (
	"bytes"
	"fmt"
)

// ConditionsMatch evaluates only the conditions of the statement at the
// zero-based, declaration-order statementIndex. It is not authorization: action,
// resource and principal selectors are not evaluated, and other statements have
// no effect on the result. A statement without conditions matches.
//
// Request validation and context cardinality follow ordinary evaluation, so
// Action and Resource must still be valid. Conditions retain ordinary variable
// expansion and the original statement effect, including malformed ARN policy
// operands matching Deny but not Allow when the request ARN is valid.
// A nil document or an out-of-range index returns an error wrapping
// ErrInvalidRequest.
func (d *Document) ConditionsMatch(statementIndex int, request Request) (bool, error) {
	if d == nil || statementIndex < 0 || statementIndex >= len(d.statements) {
		return false, fmt.Errorf("%w: condition query statement index %d is out of range", ErrInvalidRequest, statementIndex)
	}
	context, err := requestContext(request)
	if err != nil {
		return false, err
	}
	return matchesRequestConditions(d.statements[statementIndex], context, false, nil), nil
}

func matchesRequestConditions(st statement, context evaluationContext, simulation bool, trace *statementTrace) bool {
	trace.outcome(ConditionsMismatch)
	for _, condition := range st.conditions {
		if condition.op.kind != nullKind && condition.op.quantifier == singleValue && context.multivalued(condition.key) && (simulation || len(context.values[condition.key]) != 0) {
			trace.condition(condition, context.values, false, nil)
			return false
		}
		expanded := expandCondition(condition, context)
		values := context.values[condition.key]
		matches, err := expanded.matches(values, context.nonNull(condition.key), simulation)
		if err != nil {
			// A malformed ARN policy operand cannot grant access, but AWS
			// treats it as matching a Deny when the request ARN is valid.
			matches = st.effect == ExplicitDeny
		}
		trace.condition(condition, context.values, matches, err)
		if !matches {
			return false
		}
	}
	return true
}

func (c condition) matches(requestValues []string, nonNull, simulation bool) (bool, error) {
	isNull := !nonNull
	// Empty policy condition arrays do not match present values, even with a
	// negated operator. ForAllValues and IfExists retain their missing-key
	// behavior. See IAM Access Analyzer's EMPTY_ARRAY_CONDITION checks.
	if len(c.values) == 0 {
		switch c.op.quantifier {
		case allValues:
			return len(requestValues) == 0, nil
		case anyValue:
			return false, nil
		default:
			return c.op.ifExists && isNull, nil
		}
	}
	if c.op.kind == nullKind {
		for _, value := range c.values {
			if isNull == value.boolean {
				return true, nil
			}
		}
		return false, nil
	}
	if c.op.quantifier != singleValue {
		// Set quantification is outside the underlying comparison. An empty
		// request set satisfies ForAllValues and never ForAnyValue, including
		// negated comparisons and comparisons with an IfExists suffix.
		result := c.op.quantifier == allValues
		for _, raw := range requestValues {
			matched, err := c.matchesValue(raw, simulation)
			if err != nil {
				return false, err
			}
			if c.op.quantifier == allValues && !matched {
				return false, nil
			}
			if c.op.quantifier == anyValue && matched {
				result = true
			}
		}
		return result, nil
	}
	if len(requestValues) == 0 {
		return c.op.ifExists && isNull || c.op.negated, nil
	}
	return c.matchesValue(requestValues[0], simulation)
}

func (c condition) matchesValue(text string, simulation bool) (bool, error) {
	request, err := compileValue(c.op.kind, text, false)
	if err != nil {
		// Numeric/date conversion failures are unequal in ordinary IAM
		// authorization. IAM simulation instead rejects an unconvertible
		// numeric comparison before negation. Invalid IP/ARN values never
		// match, including negated operators. See the native tagging captures.
		return c.op.negated && (c.op.kind == dateKind || c.op.kind == numericKind && !simulation), nil
	}
	matched := false
	for _, value := range c.values {
		if simulation && c.op.kind == ipKind && value.invalid {
			// Simulation stops at an invalid IP policy operand before applying
			// negation. STS instead treats that operand as a nonmatch. A prior
			// matching operand already short-circuited either comparison.
			return false, nil
		}
		if value.invalid && c.op.kind == arnKind {
			return false, fmt.Errorf("%w: %s/%s has a malformed ARN policy operand", ErrInvalidPolicy, c.name, c.key)
		}
		if compareValue(c.op, request, value) {
			matched = true
			break
		}
	}
	// Policy values combine with OR for positive operators and NOR for
	// negated operators. Negating each comparison separately would allow
	// matches that AWS denies whenever there is more than one policy value.
	if c.op.negated {
		matched = !matched
	}
	return matched, nil
}

func compareValue(op operator, request, policy conditionValue) bool {
	if policy.absent || policy.invalid {
		return false
	}
	switch op.kind {
	case stringKind:
		switch op.comparison {
		case equal:
			return request.text == policy.text
		case equalFold:
			return conditionLower(request.text) == conditionLower(policy.text)
		case like:
			if policy.pattern != nil {
				return matchPattern(policy.pattern, request.text, false)
			}
			return wildcardMatch(policy.text, request.text, false)
		}
	case arnKind:
		if policy.pattern != nil {
			return matchARNPattern(policy.pattern, request.text)
		}
		return policy.text == "*" || arnMatch(policy.text, request.text)
	case numericKind:
		return compareOrdered(op.comparison, request.number.Cmp(policy.number))
	case dateKind:
		return compareOrdered(op.comparison, request.date.Compare(policy.date))
	case boolKind:
		return request.boolean == policy.boolean
	case binaryKind:
		return bytes.Equal(request.bytes, policy.bytes)
	case ipKind:
		return policy.prefix.Contains(request.address)
	}
	return false
}

func compareOrdered(op comparison, order int) bool {
	switch op {
	case equal:
		return order == 0
	case less:
		return order < 0
	case lessEqual:
		return order <= 0
	case greater:
		return order > 0
	case greaterEqual:
		return order >= 0
	}
	return false
}
