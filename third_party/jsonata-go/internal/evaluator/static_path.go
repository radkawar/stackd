package evaluator

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

// StaticPathPlan is an immutable description of a root field path. It is
// deliberately narrow: expressions with any dynamic path semantics are not
// represented and must use the normal evaluator.
type StaticPathPlan struct {
	fields          []string
	registryAliases []string
}

const (
	staticPathMaxFields = 64
	// Leave substantial headroom for evaluation work after input validation.
	// The normal evaluator's default budget is 100,000 operations.
	staticPathMaxWork = defaultMaxOperations / 4
)

// RegistryConflict reports whether a binding can shadow one of the path
// fields. Unrelated extensions and variables do not affect a static field
// path and therefore do not disable the plan.
func (p *StaticPathPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	return staticPathsRegistryConflict(registry, p.registryAliases, p.fields)
}

// BuildStaticPathPlan recognizes only a root/context path made from field
// names. The returned plan owns a copy of all path data and is safe for
// concurrent use.
func BuildStaticPathPlan(n syntax.Node) *StaticPathPlan {
	fields, ok := staticPathFields(n)
	if !ok || len(fields) == 0 || len(fields) > staticPathMaxFields {
		return nil
	}
	owned := append([]string(nil), fields...)
	return &StaticPathPlan{fields: owned, registryAliases: staticRegistryAliases(fields)}
}

func staticPathFields(n syntax.Node) ([]string, bool) {
	switch x := n.(type) {
	case syntax.Name:
		if x.Value == "" || strings.HasPrefix(x.Value, "$") {
			return nil, false
		}
		return []string{x.Value}, true
	case syntax.Variable:
		// A bare context/root expression has no field to extract.
		return nil, false
	case syntax.Binary:
		if x.Op != "." {
			return nil, false
		}
		left, leftRoot := staticPathBase(x.Left)
		right, ok := staticPathFields(x.Right)
		if !ok {
			return nil, false
		}
		if !leftRoot {
			return nil, false
		}
		return append(left, right...), true
	case syntax.Path:
		base, root := staticPathBase(x.Base)
		if !root || len(x.Fields) == 0 {
			return nil, false
		}
		for _, field := range x.Fields {
			if field.Value == "" || strings.HasPrefix(field.Value, "$") {
				return nil, false
			}
			base = append(base, field.Value)
		}
		return base, true
	default:
		return nil, false
	}
}

func staticPathBase(n syntax.Node) ([]string, bool) {
	switch x := n.(type) {
	case syntax.Variable:
		return nil, x.Kind == syntax.VariableFocus || x.Kind == syntax.VariableRoot
	case syntax.Name:
		if x.Value == "" || strings.HasPrefix(x.Value, "$") {
			return nil, false
		}
		return []string{x.Value}, true
	case syntax.Binary:
		if x.Op != "." {
			return nil, false
		}
		return staticPathFields(x)
	case syntax.Path:
		return staticPathFields(x)
	default:
		return nil, false
	}
}

// EvalStaticPath evaluates a plan only when the input shape makes the result
// unambiguously scalar. A false ok value tells the caller to use the complete
// evaluator, preserving projections, undefined handling, and ownership rules.
func EvalStaticPath(plan *StaticPathPlan, input any) (result any, ok bool) {
	if plan == nil {
		return nil, false
	}
	current, found, valid := staticPathSelectAndValidate(input, plan.fields, defaultMaxCallDepth)
	if !valid || !found {
		return nil, false
	}
	switch current.(type) {
	case map[string]any, []any, value.Array, value.OrderedObject, sequence:
		return nil, false
	}
	public, valid := value.Public(current)
	if !valid {
		return nil, false
	}
	return public, true
}

// staticPathSelectAndValidate selects a root map path while validating the
// complete input graph. The selected branch is followed only when its key
// matches the next path field; every other branch is still walked so invalid,
// unsupported, cyclic, or over-budget unrelated values retain fallback
// behavior. A selected container is recorded but remains ambiguous to the
// caller, matching EvalStaticPath's existing boundary.
func staticPathSelectAndValidate(input any, fields []string, maxDepth int) (selected any, found, valid bool) {
	if len(fields) == 0 {
		return nil, false, false
	}
	validator := staticPathSelectionValidator{
		fields:   fields,
		work:     staticPathMaxWork,
		maxDepth: maxDepth,
	}
	valid = validator.walk(input, 1, 0, true)
	return validator.selected, validator.found, valid
}

type staticPathSelectionValidator struct {
	fields   []string
	selected any
	found    bool
	work     int
	maxDepth int
}

func (v *staticPathSelectionValidator) walk(input any, depth, pathIndex int, followsPath bool) bool {
	if v.work <= 0 {
		return false
	}
	v.work--
	if v.maxDepth > 0 && depth > v.maxDepth {
		return false
	}

	switch current := input.(type) {
	case nil, bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		v.selectTerminal(input, pathIndex, followsPath)
		return true
	case float32:
		if math.IsNaN(float64(current)) || math.IsInf(float64(current), 0) {
			return false
		}
		v.selectTerminal(input, pathIndex, followsPath)
		return true
	case float64:
		if math.IsNaN(current) || math.IsInf(current, 0) {
			return false
		}
		v.selectTerminal(input, pathIndex, followsPath)
		return true
	case json.Number:
		number, err := current.Float64()
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return false
		}
		v.selectTerminal(input, pathIndex, followsPath)
		return true
	case map[string]any:
		v.selectTerminal(input, pathIndex, followsPath)
		if current == nil {
			return true
		}
		if pathIndex == len(v.fields) {
			followsPath = false
		}
		for field, item := range current {
			childFollows := followsPath && pathIndex < len(v.fields) && field == v.fields[pathIndex]
			childIndex := pathIndex
			if childFollows {
				childIndex++
			}
			if !v.walk(item, depth+1, childIndex, childFollows) {
				return false
			}
		}
		return true
	case []any:
		v.selectTerminal(input, pathIndex, followsPath)
		if current == nil {
			return true
		}
		for _, item := range current {
			if !v.walk(item, depth+1, 0, false) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (v *staticPathSelectionValidator) selectTerminal(input any, pathIndex int, followsPath bool) {
	if followsPath && pathIndex == len(v.fields) {
		v.selected = input
		v.found = true
	}
}

// staticPathInputSafe mirrors the ordinary JSON subset accepted by the input
// normalizer. It deliberately declines reflected/named values; those inputs
// are uncommon on this path and the full evaluator remains authoritative for
// them. The walk is needed even for unrelated branches because Eval copies and
// validates the complete input before evaluation. Cycles are rejected by the
// same bounded depth check used by normal input validation. Repeated aliases
// are traversed independently, so aliases remain valid while cycles cannot
// recurse without reaching the bound.
func staticPathInputSafe(input any, maxDepth int) bool {
	work := staticPathMaxWork
	return staticPathValueSafe(input, 1, maxDepth, &work)
}

func staticPathValueSafe(input any, depth, maxDepth int, work *int) bool {
	if *work <= 0 {
		return false
	}
	*work--
	if maxDepth > 0 && depth > maxDepth {
		return false
	}
	switch current := input.(type) {
	case nil, bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	case float32:
		return !math.IsNaN(float64(current)) && !math.IsInf(float64(current), 0)
	case float64:
		return !math.IsNaN(current) && !math.IsInf(current, 0)
	case json.Number:
		number, err := current.Float64()
		return err == nil && !math.IsNaN(number) && !math.IsInf(number, 0)
	case map[string]any:
		if current == nil {
			return true
		}
		for _, item := range current {
			if !staticPathValueSafe(item, depth+1, maxDepth, work) {
				return false
			}
		}
		return true
	case []any:
		if current == nil {
			return true
		}
		for _, item := range current {
			if !staticPathValueSafe(item, depth+1, maxDepth, work) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
