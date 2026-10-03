package evaluator

import (
	jsonregex "github.com/tiaanduplessis/jsonata-go/internal/regex"
	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
)

// StaticContainsPlan describes the only regex shortcut that is safe to use
// without evaluating the complete expression tree: a field-only path and a
// parsed regex literal. The regex product is immutable and is shared by all
// evaluations of the compiled expression.
type StaticContainsPlan struct {
	path    []string
	pattern jsonregex.Pattern
}

// BuildStaticContainsPlan recognises $contains(static.path, /literal/).
// Function values, string patterns, dynamic paths, and non-literal patterns
// remain on the normal evaluator path because their coercion and binding
// rules are observable.
func BuildStaticContainsPlan(n syntax.Node) *StaticContainsPlan {
	call, ok := n.(syntax.Call)
	if !ok || call.Partial || len(call.Args) != 2 {
		return nil
	}
	if !staticContainsFunction(call.Function) {
		return nil
	}
	path, ok := staticPathFields(call.Args[0])
	if !ok || len(path) == 0 || len(path) > staticPathMaxFields {
		return nil
	}
	literal, ok := call.Args[1].(syntax.Literal)
	if !ok || literal.Kind != syntax.Regex || !literal.RegexParsed {
		return nil
	}
	return &StaticContainsPlan{
		path:    append([]string(nil), path...),
		pattern: literal.RegexValue,
	}
}

func staticContainsFunction(n syntax.Node) bool {
	switch function := n.(type) {
	case syntax.Variable:
		return function.Name == "$contains"
	case syntax.Name:
		return function.Value == "$contains"
	default:
		return false
	}
}

// RegistryConflict also covers an override of $contains itself. A registry
// entry for an unrelated function or field cannot affect this plan.
func (p *StaticContainsPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	if _, exists := registry["contains"]; exists {
		return true
	}
	if _, exists := registry["$contains"]; exists {
		return true
	}
	return staticFieldsRegistryConflict(p.path, registry)
}

// EvalStaticContains evaluates a decoded input only after validating the
// complete value graph. Missing, null, containers, non-strings, cycles,
// unsupported values, non-finite numbers, and over-budget inputs all fall
// back to the complete evaluator, preserving its public diagnostics.
func EvalStaticContains(plan *StaticContainsPlan, input any) (bool, bool) {
	if plan == nil || !staticPathInputSafe(input, defaultMaxCallDepth) {
		return false, false
	}
	valueAtPath, ok := staticScalarAtPath(input, plan.path)
	if !ok {
		return false, false
	}
	text, ok := valueAtPath.(string)
	if !ok {
		return false, false
	}
	// The full builtin charges one operation per input byte before matching.
	// Decline oversized strings so the normal evaluator can return its stable
	// operation-budget error instead of allowing this shortcut to bypass it.
	if len(text)+staticPathMaxWork+64 > defaultMaxOperations {
		return false, false
	}
	matched, err := plan.pattern.MatchStringStatic(text)
	if err != nil {
		// A bounded fallback timeout is not a semantic result. Let the full
		// evaluator report its normal resource error and diagnostic metadata.
		return false, false
	}
	return matched, true
}
