package evaluator

import (
	"math"
	"sort"

	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
)

// StaticDescendantSumPlan describes the narrow decoded-input form
// $sum(static.path.**.field). It intentionally does not cover bytes input:
// duplicate JSON object members and source ordering must remain governed by
// the normal decoder and evaluator.
type StaticDescendantSumPlan struct {
	head  []string
	field string
}

// BuildStaticDescendantSumPlan recognises the AST shape of a built-in sum
// over a recursive descendant path. The plan contains no source text and is
// immutable after construction.
func BuildStaticDescendantSumPlan(n syntax.Node) *StaticDescendantSumPlan {
	call, ok := n.(syntax.Call)
	if !ok || call.Partial || len(call.Args) != 1 {
		return nil
	}
	function, ok := call.Function.(syntax.Variable)
	if !ok || function.Kind != syntax.VariableNamed || function.Name != "$sum" {
		return nil
	}
	outer, ok := call.Args[0].(syntax.Binary)
	if !ok || outer.Op != "." {
		return nil
	}
	field, ok := outer.Right.(syntax.Name)
	if !ok || field.Value == "" {
		return nil
	}
	inner, ok := outer.Left.(syntax.Binary)
	if !ok || inner.Op != "." {
		return nil
	}
	wildcard, ok := inner.Right.(syntax.Wildcard)
	if !ok || !wildcard.Recursive {
		return nil
	}
	head, ok := staticPathFields(inner.Left)
	if !ok || len(head) == 0 || len(head)+1 > staticPathMaxFields {
		return nil
	}
	return &StaticDescendantSumPlan{
		head:  append([]string(nil), head...),
		field: field.Value,
	}
}

// RegistryConflict reports whether a registered name can alter either the
// built-in reduction, the static path, or the descendant field lookup.
func (p *StaticDescendantSumPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	if _, exists := registry["sum"]; exists {
		return true
	}
	if _, exists := registry["$sum"]; exists {
		return true
	}
	if staticFieldsRegistryConflict(p.head, registry) {
		return true
	}
	return staticFieldsRegistryConflict([]string{p.field}, registry)
}

// EvalStaticDescendantSum evaluates a plan only when every observable value
// is unambiguous for the ordinary evaluator. Missing fields on descendants
// are ignored, as they are by the descendant path; no matching numeric field
// causes fallback so the public undefined result remains available. A
// matching array, object, nonnumeric value, nonfinite value, or overflow also
// causes fallback.
func EvalStaticDescendantSum(plan *StaticDescendantSumPlan, input any) (any, bool) {
	if plan == nil || !staticPathInputSafe(input, defaultMaxCallDepth) {
		return nil, false
	}
	return evalStaticDescendantSumValidated(plan, input)
}

func evalStaticDescendantSumValidated(plan *StaticDescendantSumPlan, input any) (any, bool) {
	if plan == nil {
		return nil, false
	}
	work := staticPathMaxWork
	roots, ok := staticDescendantRoots(input, plan.head, &work)
	if !ok || len(roots) == 0 {
		return nil, false
	}
	var total float64
	matched := false
	for _, root := range roots {
		if !staticDescendantSumVisit(root, plan.field, &work, &total, &matched) {
			return nil, false
		}
	}
	if !matched || math.IsNaN(total) || math.IsInf(total, 0) {
		return nil, false
	}
	return total, true
}

// staticDescendantRoots follows the ordinary field path's array projection
// without flattening nested terminal arrays. This is sufficient to preserve
// the root/path boundary while still handling a path through an array of
// objects.
func staticDescendantRoots(input any, fields []string, work *int) ([]any, bool) {
	if !staticDescendantConsume(work) {
		return nil, false
	}
	if len(fields) == 0 {
		return []any{input}, true
	}
	switch current := input.(type) {
	case map[string]any:
		item, ok := current[fields[0]]
		if !ok {
			return nil, true
		}
		return staticDescendantRoots(item, fields[1:], work)
	case []any:
		roots := make([]any, 0, len(current))
		for _, item := range current {
			children, ok := staticDescendantRoots(item, fields, work)
			if !ok {
				return nil, false
			}
			roots = append(roots, children...)
		}
		return roots, true
	default:
		return nil, true
	}
}

func staticDescendantSumVisit(current any, field string, work *int, total *float64, matched *bool) bool {
	if !staticDescendantConsume(work) {
		return false
	}
	switch value := current.(type) {
	case map[string]any:
		if candidate, exists := value[field]; exists {
			number, ok := strictNumeric(candidate)
			if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
				return false
			}
			*total += number
			if math.IsNaN(*total) || math.IsInf(*total, 0) {
				return false
			}
			*matched = true
		}
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !staticDescendantSumVisit(value[key], field, work, total, matched) {
				return false
			}
		}
	case []any:
		for _, item := range value {
			if !staticDescendantSumVisit(item, field, work, total, matched) {
				return false
			}
		}
	}
	return true
}

func staticDescendantConsume(work *int) bool {
	if *work <= 0 {
		return false
	}
	*work--
	return true
}
