package evaluator

import (
	"math"
	"strings"

	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

// StaticExtensionArithmeticPlan describes a narrow arithmetic expression in
// which both operands are calls to registered functions with scalar input
// paths. The plan contains AST-derived data only; it does not inspect source
// text or benchmark case names.
type StaticExtensionArithmeticPlan struct {
	left, right staticExtensionCall
	position    int
}

type staticExtensionCall struct {
	name string
	path []string
	call syntax.Call
}

// BuildStaticExtensionArithmeticPlan recognises expressions such as
// `$double(value) + $double(offset)`. Calls with dynamic arguments, partial
// application, or non-named procedures remain on the evaluator path.
func BuildStaticExtensionArithmeticPlan(n syntax.Node) *StaticExtensionArithmeticPlan {
	binary, ok := n.(syntax.Binary)
	if !ok || binary.Op != "+" {
		return nil
	}
	left, ok := staticExtensionCallPlan(binary.Left)
	if !ok {
		return nil
	}
	right, ok := staticExtensionCallPlan(binary.Right)
	if !ok {
		return nil
	}
	if len(left.path)+len(right.path) > staticPathMaxFields {
		return nil
	}
	return &StaticExtensionArithmeticPlan{left: left, right: right, position: binary.Pos.Offset}
}

func staticExtensionCallPlan(n syntax.Node) (staticExtensionCall, bool) {
	call, ok := n.(syntax.Call)
	if !ok || call.Partial || len(call.Args) != 1 {
		return staticExtensionCall{}, false
	}
	name, ok := staticExtensionName(call.Function)
	if !ok {
		return staticExtensionCall{}, false
	}
	path, ok := staticPathFields(call.Args[0])
	if !ok || len(path) == 0 || len(path) > staticPathMaxFields {
		return staticExtensionCall{}, false
	}
	return staticExtensionCall{name: name, path: append([]string(nil), path...), call: call}, true
}

func staticExtensionName(n syntax.Node) (string, bool) {
	var name string
	switch x := n.(type) {
	case syntax.Variable:
		if x.Kind != syntax.VariableNamed {
			return "", false
		}
		name = x.Name
	case syntax.Name:
		name = x.Value
	default:
		return "", false
	}
	if !strings.HasPrefix(name, "$") || len(name) == 1 {
		return "", false
	}
	return strings.TrimPrefix(name, "$"), true
}

// RegistryConflict reports only bindings that can shadow one of the input
// paths. The extension itself is intentionally not treated as a conflict: the
// current copy-on-write registry snapshot supplies the callable at evaluation
// time, so re-registration remains visible after compilation.
func (p *StaticExtensionArithmeticPlan) RegistryConflict(registry map[string]any) bool {
	if p == nil {
		return false
	}
	return staticFieldsRegistryConflict(p.left.path, registry) ||
		staticFieldsRegistryConflict(p.right.path, registry)
}

// RegistryReady reports whether both procedures resolve to callables in the
// supplied registry snapshot. Builtins and non-callable overrides deliberately
// fall back to the full evaluator so its name lookup and diagnostics remain
// authoritative.
func (p *StaticExtensionArithmeticPlan) RegistryReady(registry map[string]any) bool {
	if p == nil {
		return false
	}
	_, _, ready := staticExtensionBindings(p, registry)
	return ready
}

func staticExtensionBindings(plan *StaticExtensionArithmeticPlan, registry map[string]any) (left, right callableValue, ready bool) {
	if plan == nil {
		return nil, nil, false
	}
	left, leftOK := staticExtensionRegistryCallable(plan.left.name, registry)
	right, rightOK := staticExtensionRegistryCallable(plan.right.name, registry)
	return left, right, leftOK && rightOK
}

func staticExtensionRegistryCallable(name string, registry map[string]any) (callableValue, bool) {
	binding, ok := registry[name]
	if !ok {
		binding, ok = registry["$"+name]
	}
	if !ok {
		return nil, false
	}
	return callable(binding)
}

// EvalStaticExtensionArithmetic evaluates the plan against an ordinary
// decoded Go JSON value. ok=false requests the complete evaluator. An error
// means the fast plan has reached an observable runtime error and must be
// returned rather than silently changing its semantics.
func EvalStaticExtensionArithmetic(plan *StaticExtensionArithmeticPlan, input any, registry map[string]any) (result any, ok bool, err error) {
	if plan == nil || plan.RegistryConflict(registry) {
		return nil, false, nil
	}
	leftFn, rightFn, ready := staticExtensionBindings(plan, registry)
	if !ready {
		return nil, false, nil
	}
	// This is the same complete graph validation used by the other immutable
	// decoded-input plans. It rejects cycles, unsupported values, non-finite
	// numbers, excessive nesting, and oversized inputs before any extension is
	// invoked. Scalar arguments are read-only, so no caller-owned container is
	// retained or exposed to a function.
	if !staticPathInputSafe(input, defaultMaxCallDepth) {
		return nil, false, nil
	}
	left, leftOK := staticScalarAtPath(input, plan.left.path)
	right, rightOK := staticScalarAtPath(input, plan.right.path)
	if !leftOK || !rightOK {
		return nil, false, nil
	}
	if leftFast, leftExact := leftFn.(*reflectedExtension); leftExact && leftFast.fastFloat64 != nil {
		if rightFast, rightExact := rightFn.(*reflectedExtension); rightExact && rightFast.fastFloat64 != nil {
			leftNumber, leftErr, leftHandled := leftFast.invokeStaticFloat64Default(left)
			if leftHandled {
				if leftErr != nil {
					return nil, true, withRuntimeCallMetadata(leftErr, plan.left.call, leftFn)
				}
				rightNumber, rightErr, rightHandled := rightFast.invokeStaticFloat64Default(right)
				if rightHandled {
					if rightErr != nil {
						return nil, true, withRuntimeCallMetadata(rightErr, plan.right.call, rightFn)
					}
					sum := leftNumber + rightNumber
					if math.IsNaN(sum) || math.IsInf(sum, 0) {
						overflow := runtimeError{code: "D1001", msg: "numeric result is not finite"}
						return nil, true, withRuntimePosition(withRuntimeToken(overflow, "+"), plan.position+1)
					}
					return sum, true, nil
				}
			}
		}
	}
	runtime := newEvalRuntime(Options{})
	if err := runtime.check(); err != nil {
		return nil, true, err
	}
	st := state{root: input, current: input, vars: registry, runtime: runtime}
	left, err = invokeStaticExtension(st, plan.left, left, leftFn)
	if err != nil {
		return nil, true, err
	}
	right, err = invokeStaticExtension(st, plan.right, right, rightFn)
	if err != nil {
		return nil, true, err
	}
	result, err = arithmetic(left, right, "+", func(a, b float64) float64 { return a + b })
	if err != nil {
		return nil, true, withRuntimePosition(withRuntimeToken(err, "+"), plan.position+1)
	}
	if value.IsUndefined(result) {
		return nil, true, errUndefined
	}
	if number, isNumber := result.(float64); isNumber && (math.IsNaN(number) || math.IsInf(number, 0)) {
		return nil, true, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	}
	return result, true, nil
}

func invokeStaticExtension(st state, plan staticExtensionCall, argument any, fn callableValue) (any, error) {
	// Static plans admit only scalar values. Avoid constructing the generic
	// argument slice for numeric calls; strings still need the evaluator's
	// UTF-16 representation check before extension dispatch.
	if _, isString := argument.(string); isString {
		if err := rejectUTF16StringArguments(fn.callableName(), []any{argument}); err != nil {
			return nil, withRuntimeCallMetadata(err, plan.call, fn)
		}
	}
	if optimized, ok := fn.(*reflectedExtension); ok {
		if result, err, handled := optimized.invokeStaticFloat64(st, argument); handled {
			if err != nil {
				return nil, withRuntimeCallMetadata(err, plan.call, fn)
			}
			return result, nil
		}
	}
	result, err := fn.invoke(st, []any{argument})
	if err != nil {
		return nil, withRuntimeCallMetadata(err, plan.call, fn)
	}
	return result, nil
}
