// Package evaluator contains the pure, per-call JSONata evaluator.
package evaluator

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"

	jsonregex "github.com/tiaanduplessis/jsonata-go/internal/regex"
	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

var errUndefined = errors.New("undefined")

const bulkOperationCheckStride = 256

func bulkOperationCapacity(total int, runtime *evalRuntime) int {
	if runtime == nil {
		return total
	}
	if total <= 0 || runtime.budget <= 0 {
		return 0
	}
	checksNeeded := (total-1)/bulkOperationCheckStride + 1
	if runtime.budget >= int64(checksNeeded) {
		return total
	}
	return int(runtime.budget) * bulkOperationCheckStride
}

// IsUndefined reports whether an evaluation returned the empty-sequence
// sentinel. Callers should use this helper instead of comparing error text.
func IsUndefined(err error) bool {
	return errors.Is(err, errUndefined)
}

type runtimeError struct {
	code     string
	msg      string
	cause    error
	token    string
	value    any
	position int
	hasPos   bool
}

func (e runtimeError) Error() string                { return e.msg }
func (e runtimeError) JSONataCode() string          { return e.code }
func (e runtimeError) Unwrap() error                { return e.cause }
func (e runtimeError) JSONataToken() string         { return e.token }
func (e runtimeError) JSONataValue() any            { return e.value }
func (e runtimeError) JSONataPosition() (int, bool) { return e.position, e.hasPos }

func withRuntimeToken(err error, token string) error {
	if token == "" || err == nil {
		return err
	}
	switch typed := err.(type) {
	case runtimeError:
		if typed.token == "" {
			typed.token = token
		}
		return typed
	case *runtimeError:
		if typed != nil && typed.token == "" {
			copy := *typed
			copy.token = token
			return copy
		}
	}
	return err
}

func withRuntimePosition(err error, position int) error {
	if err == nil {
		return nil
	}
	switch typed := err.(type) {
	case runtimeError:
		if !typed.hasPos {
			typed.position = position
			typed.hasPos = true
		}
		return typed
	case *runtimeError:
		if typed != nil && !typed.hasPos {
			copy := *typed
			copy.position = position
			copy.hasPos = true
			return copy
		}
	}
	return err
}

// withRuntimeCallMetadata models jsonata-js's evaluateFunction/apply error
// boundary. Errors raised while evaluating the procedure or its arguments
// are returned before this helper is called and therefore retain their own
// source metadata. Errors raised by the invocation itself receive the call
// position, while an operator or other inner token remains authoritative.
func withRuntimeCallMetadata(err error, call syntax.Call, fn any) error {
	if err == nil {
		return nil
	}
	if !call.ProcedureGrouped {
		err = withRuntimeToken(err, callProcedureToken(call.Function, fn))
	}
	return withRuntimePositionAlways(err, call.Pos.Offset+1)
}

func withRuntimePositionAlways(err error, position int) error {
	if err == nil {
		return nil
	}
	switch typed := err.(type) {
	case runtimeError:
		typed.position = position
		typed.hasPos = true
		return typed
	case *runtimeError:
		if typed != nil {
			copy := *typed
			copy.position = position
			copy.hasPos = true
			return copy
		}
	}
	return err
}

func callProcedureToken(node syntax.Node, _ any) string {
	switch typed := node.(type) {
	case syntax.Name:
		return strings.TrimPrefix(typed.Value, "$")
	case syntax.Variable:
		return strings.TrimPrefix(typed.Name, "$")
	case syntax.Literal:
		return toString(typed.Value)
	}
	return ""
}

type sequence = value.Sequence
type bound struct {
	v    any
	vars map[string]any
}
type contextual struct {
	v, parent any
	vars      map[string]any
	lineage   bool
}
type sortedSequence struct {
	values     any
	descending bool
	keep       bool
}
type sortKeyPart struct {
	value      any
	descending bool
}
type sortTuple []sortKeyPart

type regexValue struct {
	pattern jsonregex.Pattern
}

func (r regexValue) callableName() string { return "regular expression" }

func (r regexValue) invoke(st state, args []any) (any, error) {
	if err := regexCheck(st); err != nil {
		return nil, err
	}
	if len(args) != 1 {
		return nil, functionArityError("regular expression", 1, len(args))
	}
	if value.IsUndefined(collapse(args[0])) {
		return value.Undefined, nil
	}
	input, ok := regexStringArgument(args[0])
	if !ok {
		return nil, runtimeError{code: "T0410", msg: "regular expression input must be a string"}
	}
	matches, err := regexFindAll(st, r.pattern, input, 1)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return value.Undefined, nil
	}
	return regexMatcherObject(r, input, matches[0])
}

type regexNextValue struct {
	pattern regexValue
	input   string
	start   int
}

func (r regexNextValue) callableName() string { return "regular expression next matcher" }

func (r regexNextValue) invoke(st state, args []any) (any, error) {
	if err := regexCheck(st); err != nil {
		return nil, err
	}
	if len(args) != 0 {
		return nil, functionArityError("regular expression next matcher", 0, len(args))
	}
	matches, err := regexFindAll(st, r.pattern.pattern, r.input, -1)
	if err != nil {
		return nil, err
	}
	for _, indexes := range matches {
		if indexes[0] < r.start {
			continue
		}
		if indexes[0] == indexes[1] {
			return nil, runtimeError{code: "D1004", msg: "regular expression matched an empty string"}
		}
		return regexMatcherObject(r.pattern, r.input, indexes)
	}
	return value.Undefined, nil
}

type state struct {
	root, current, parent any
	vars                  map[string]any
	env                   *lexicalEnv
	runtime               *evalRuntime
	tail                  bool
	preserveObjectOrder   bool
	allowNonFinite        bool
}

func Eval(n syntax.Node, input any) (any, error) {
	return EvalWithOptions(n, input, Options{})
}

// EvalBindings evaluates with an isolated binding map. Both "name" and
// "$name" keys are accepted because fixtures and compatibility callers use
// both forms.
func EvalBindings(n syntax.Node, input any, bindings map[string]any) (any, error) {
	return EvalBindingsWithOptions(n, input, bindings, Options{})
}

func EvalWithOptions(n syntax.Node, input any, options Options) (any, error) {
	return evalWithOptions(n, input, options, true)
}

func EvalBindingsWithOptions(n syntax.Node, input any, bindings map[string]any, options Options) (any, error) {
	options.Bindings = bindings
	return evalWithOptions(n, input, options, true)
}

// EvalNoInputWithOptions evaluates with the JSONata empty input sequence.
// This is distinct from EvalWithOptions with nil, which represents JSON null.
func EvalNoInputWithOptions(n syntax.Node, options Options) (any, error) {
	return evalWithOptions(n, value.Undefined, options, false)
}

func EvalNoInputBindingsWithOptions(n syntax.Node, bindings map[string]any, options Options) (any, error) {
	options.Bindings = bindings
	return evalWithOptions(n, value.Undefined, options, false)
}

func evalWithOptions(n syntax.Node, input any, options Options, hasInput bool) (any, error) {
	runtime := newEvalRuntime(options)
	return evalWithRuntime(n, input, options.Bindings, runtime, hasInput, true)
}

func evalWithRuntime(n syntax.Node, input any, bindings map[string]any, runtime *evalRuntime, hasInput, normalizeInput bool) (any, error) {
	if hasInput {
		if normalizeInput {
			var err error
			input, err = normalizeInputValue(runtime, input)
			if err != nil {
				return nil, err
			}
		}
	}
	var vars, normalizedBindings map[string]any
	if len(bindings) != 0 {
		vars = make(map[string]any, len(bindings)*2)
		normalizedBindings = make(map[string]any, len(bindings))
	}
	for k, v := range bindings {
		normalized, err := normalizeExtensionValue(runtime, v)
		if err != nil {
			return nil, withRuntimeToken(err, k)
		}
		normalizedBindings[k] = normalized
		vars[k] = normalized
	}
	for k, v := range normalizedBindings {
		if strings.HasPrefix(k, "$") {
			vars[k[1:]] = v
			continue
		}
		if _, exact := normalizedBindings["$"+k]; !exact {
			vars["$"+k] = v
		}
	}
	var env *lexicalEnv
	if len(vars) != 0 {
		// The root frame is immutable for the duration of an evaluation. Reuse
		// the binding map instead of allocating an empty frame and copying it
		// into a second map. Nested scopes still use bindFrame, which copies
		// their values before any state can mutate them.
		env = &lexicalEnv{values: vars}
	}
	return evalPublic(n, state{root: input, current: input, vars: vars, env: env, runtime: runtime})
}

func evalPublic(n syntax.Node, st state) (any, error) {
	v, err := eval(n, st)
	if err != nil {
		return nil, err
	}
	if err := checkSequenceResult(v, st.runtime); err != nil {
		return nil, err
	}
	v = unwrapSorted(collapse(v))
	if value.IsUndefined(v) {
		return nil, errUndefined
	}
	if containsCallable(v) {
		return nil, runtimeError{code: "T1007", msg: "function value cannot be returned as JSON"}
	}
	if containsUTF16String(v) {
		return nil, unsupportedUTF16StringError()
	}
	p, ok := value.Public(v)
	if !ok {
		return nil, fmt.Errorf("jsonata: result is not JSON-compatible")
	}
	return p, nil
}

func containsCallable(v any) bool {
	if _, ok := callable(v); ok {
		return true
	}
	switch x := v.(type) {
	case contextual:
		return containsCallable(x.v)
	case bound:
		return containsCallable(x.v)
	case sequence:
		for _, item := range x {
			if containsCallable(item) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if containsCallable(item) {
				return true
			}
		}
	case value.Array:
		for _, item := range x.Items {
			if containsCallable(item) {
				return true
			}
		}
	case sortedSequence:
		return containsCallable(x.values)
	case map[string]any:
		for _, item := range x {
			if containsCallable(item) {
				return true
			}
		}
	case value.OrderedObject:
		for _, item := range x.Fields {
			if containsCallable(item) {
				return true
			}
		}
	}
	return false
}

func containsUTF16String(v any) bool {
	v = unwrapSignatureValue(v)
	if _, ok := v.(syntax.UTF16String); ok {
		return true
	}
	switch current := v.(type) {
	case sequence:
		for _, item := range current {
			if containsUTF16String(item) {
				return true
			}
		}
	case []any:
		for _, item := range current {
			if containsUTF16String(item) {
				return true
			}
		}
	case value.Array:
		for _, item := range current.Items {
			if containsUTF16String(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range current {
			if containsUTF16String(item) {
				return true
			}
		}
	case value.OrderedObject:
		for _, item := range current.Fields {
			if containsUTF16String(item) {
				return true
			}
		}
	}
	return false
}

func rejectUTF16StringArguments(name string, args []any) error {
	for _, argument := range args {
		if !containsUTF16String(argument) {
			continue
		}
		if name == "encodeUrl" || name == "encodeUrlComponent" {
			return malformedURL(name, escapedUTF16Argument(argument))
		}
		return unsupportedUTF16StringError()
	}
	return nil
}

func escapedUTF16Argument(v any) string {
	v = unwrapSignatureValue(v)
	if text, ok := v.(syntax.UTF16String); ok {
		var escaped strings.Builder
		for _, unit := range text.Units {
			fmt.Fprintf(&escaped, `\u%04X`, unit)
		}
		return escaped.String()
	}
	return "unpaired UTF-16 surrogate"
}

func unsupportedUTF16StringError() error {
	return runtimeError{code: "U1002", msg: "string contains an unpaired UTF-16 surrogate"}
}

func collapse(v any) any {
	if c, ok := v.(contextual); ok {
		return collapse(c.v)
	}
	if b, ok := v.(bound); ok {
		return collapse(b.v)
	}
	if s, ok := v.(sequence); ok {
		if len(s) == 0 {
			return value.Undefined
		}
		if len(s) == 1 {
			return collapse(s[0])
		}
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = collapse(x)
		}
		return out
	}
	if a, ok := v.([]any); ok {
		out := make([]any, len(a))
		for i, item := range a {
			out[i] = collapse(item)
		}
		return out
	}
	if a, ok := v.(value.Array); ok {
		out := make([]any, len(a.Items))
		for i, item := range a.Items {
			out[i] = collapse(item)
		}
		return value.Array{Items: out, Keep: a.Keep}
	}
	if a, ok := v.(sortedSequence); ok {
		return sortedSequence{values: collapse(a.values), descending: a.descending, keep: a.keep}
	}
	if m, ok := v.(map[string]any); ok {
		out := make(map[string]any, len(m))
		for k, item := range m {
			out[k] = collapse(item)
		}
		return out
	}
	if m, ok := v.(value.OrderedObject); ok {
		out := make(map[string]any, len(m.Fields))
		for k, item := range m.Fields {
			out[k] = collapse(item)
		}
		return value.OrderedObject{Fields: out, Order: append([]string(nil), m.Order...)}
	}
	return v
}

func unwrapSorted(v any) any {
	switch x := v.(type) {
	case sortedSequence:
		return unwrapSorted(x.values)
	case []any:
		for i := range x {
			x[i] = unwrapSorted(x[i])
		}
	case value.Array:
		for i := range x.Items {
			x.Items[i] = unwrapSorted(x.Items[i])
		}
	case map[string]any:
		for key := range x {
			x[key] = unwrapSorted(x[key])
		}
	case value.OrderedObject:
		for key := range x.Fields {
			x.Fields[key] = unwrapSorted(x.Fields[key])
		}
	}
	return v
}

func sortedKeep(v any) bool {
	if x, ok := v.(value.Array); ok {
		return x.Keep
	}
	if x, ok := v.(sortedSequence); ok {
		return x.keep
	}
	return false
}

func items(v any) []any {
	switch x := v.(type) {
	case contextual:
		switch nested := x.v.(type) {
		case value.Array:
			if !nested.Keep {
				out := make([]any, 0, len(nested.Items))
				for _, item := range nested.Items {
					out = append(out, contextual{v: item, parent: x.parent, vars: cloneVars(x.vars), lineage: x.lineage})
				}
				return out
			}
		case sequence:
			out := make([]any, 0, len(nested))
			for _, item := range nested {
				out = append(out, contextual{v: item, parent: x.parent, vars: cloneVars(x.vars), lineage: x.lineage})
			}
			return out
		}
		return []any{x}
	case sequence:
		// Callers only inspect the returned values. Keep the sequence's backing
		// array instead of copying it on every path, predicate, and function
		// operation. Values are copied when they cross the public boundary or
		// are explicitly collapsed.
		return []any(x)
	case []any:
		return x
	case value.Array:
		return x.Items
	case bound:
		return []any{x}
	case sortedSequence:
		return items(x.values)
	default:
		if value.IsUndefined(v) {
			return nil
		}
		return []any{v}
	}
}

func itemsLength(v any) int {
	switch typed := v.(type) {
	case contextual:
		switch nested := typed.v.(type) {
		case value.Array:
			if !nested.Keep {
				return len(nested.Items)
			}
		case sequence:
			return len(nested)
		}
		return 1
	case sequence:
		return len(typed)
	case []any:
		return len(typed)
	case value.Array:
		return len(typed.Items)
	case bound:
		return 1
	case sortedSequence:
		return itemsLength(typed.values)
	default:
		if value.IsUndefined(v) {
			return 0
		}
		return 1
	}
}
func flatten(dst []any, v any) []any {
	switch x := v.(type) {
	case sequence:
		for _, y := range x {
			dst = flatten(dst, y)
		}
	case bound:
		dst = flatten(dst, x.v)
	case contextual:
		dst = flatten(dst, x.v)
	case sortedSequence:
		dst = flatten(dst, x.values)
	case undefinedLike:
	default:
		if !value.IsUndefined(v) {
			dst = append(dst, v)
		}
	}
	return dst
}

func checkedSequenceResult(result any, runtime *evalRuntime) (any, error) {
	if err := checkSequenceResult(result, runtime); err != nil {
		return nil, err
	}
	return result, nil
}

func checkSequenceResult(result any, runtime *evalRuntime) error {
	if runtime == nil || runtime.maxSequence == 0 {
		return nil
	}
	for {
		switch typed := result.(type) {
		case contextual:
			result = typed.v
		case bound:
			result = typed.v
		case sortedSequence:
			result = typed.values
		case sequence:
			return runtime.checkSequenceLength(len(typed))
		default:
			return nil
		}
	}
}

type undefinedLike struct{}

func eval(n syntax.Node, st state) (any, error) {
	if st.runtime != nil {
		if err := st.runtime.check(); err != nil {
			return nil, err
		}
		if err := st.runtime.enterEval(); err != nil {
			return nil, err
		}
		defer st.runtime.leaveEval()
	}
	switch x := n.(type) {
	case syntax.Literal:
		if x.Kind == syntax.Number {
			if x.NumberParsed {
				return x.NumberValue, nil
			}
			return parseNumber(x.Value.(string))
		}
		if x.Kind == syntax.Regex {
			if x.RegexParsed {
				return regexValue{pattern: x.RegexValue}, nil
			}
			literal, ok := x.Value.(string)
			if !ok {
				return nil, runtimeError{code: "S0302", msg: "invalid regular expression literal"}
			}
			pattern, err := jsonregex.CompileLiteral(literal)
			if err != nil {
				code := "S0302"
				var compileErr *jsonregex.CompileError
				if errors.As(err, &compileErr) {
					code = compileErr.Code
				}
				return nil, runtimeError{code: code, msg: err.Error(), cause: err}
			}
			return regexValue{pattern: pattern}, nil
		}
		return x.Value, nil
	case syntax.Name:
		if x.Value == "$" {
			return st.current, nil
		}
		if x.Value == "$$" {
			return st.root, nil
		}
		if x.Value == "%" {
			return st.parent, nil
		}
		if st.env != nil {
			if v, ok := st.env.lookup(x.Value); ok {
				return v, nil
			}
		}
		if v, ok := st.vars[x.Value]; ok {
			return v, nil
		}
		if strings.HasPrefix(x.Value, "$") {
			if fn, ok := builtinFor(x.Value); ok {
				return fn, nil
			}
		}
		v, err := fieldWithRuntime(st.current, x.Value, st.runtime)
		if err != nil {
			return nil, err
		}
		if value.IsUndefined(v) && hasLineageBindings(st.vars) {
			v, err = lineageField(st.parent, x.Value, st.runtime)
			if err != nil {
				return nil, err
			}
			v = inheritLineageVars(v, st.vars)
		}
		if value.IsUndefined(v) {
			v, err = fieldWithRuntime(st.root, x.Value, st.runtime)
			if err != nil {
				return nil, err
			}
		}
		return checkedSequenceResult(v, st.runtime)
	case syntax.Variable:
		if x.Name == "$" {
			return st.current, nil
		}
		if x.Name == "$$" {
			return st.root, nil
		}
		if x.Name == "%" {
			return st.parent, nil
		}
		if st.env != nil {
			if v, ok := st.env.lookup(x.Name); ok {
				return v, nil
			}
		}
		if v, ok := st.vars[x.Name]; ok {
			return v, nil
		}
		if strings.HasPrefix(x.Name, "$") {
			if fn, ok := builtinFor(x.Name); ok {
				return fn, nil
			}
		}
		v, err := fieldWithRuntime(st.current, x.Name, st.runtime)
		if err != nil {
			return nil, err
		}
		if value.IsUndefined(v) && hasLineageBindings(st.vars) {
			v, err = lineageField(st.parent, x.Name, st.runtime)
			if err != nil {
				return nil, err
			}
			v = inheritLineageVars(v, st.vars)
		}
		if value.IsUndefined(v) {
			v, err = fieldWithRuntime(st.root, x.Name, st.runtime)
			if err != nil {
				return nil, err
			}
		}
		return checkedSequenceResult(v, st.runtime)
	case syntax.Parent:
		return st.parent, nil
	case syntax.Wildcard:
		return wildcard(st.current, x.Recursive, st.runtime)
	case syntax.Array:
		out := make([]any, 0, sequenceAllocationCapacity(len(x.Items), st.runtime))
		for _, item := range x.Items {
			itemState := st
			itemState.tail = false
			v, e := eval(item, itemState)
			if e != nil {
				return nil, e
			}
			for {
				if framed, ok := v.(contextual); ok {
					v = framed.v
					continue
				}
				if framed, ok := v.(bound); ok {
					v = framed.v
					continue
				}
				break
			}
			if s, ok := v.(sequence); ok {
				if st.runtime != nil {
					if err := st.runtime.checkSequenceLengthAttempted(len(out) + len(s)); err != nil {
						return nil, err
					}
				}
				out = append(out, s...)
				continue
			}
			if a, ok := v.(value.Array); ok {
				if _, explicit := item.(syntax.Array); !explicit {
					if st.runtime != nil {
						if err := st.runtime.checkSequenceLengthAttempted(len(out) + len(a.Items)); err != nil {
							return nil, err
						}
					}
					out = append(out, a.Items...)
					continue
				}
			}
			if !value.IsUndefined(v) {
				if _, explicitNestedArray := item.(syntax.Array); !explicitNestedArray && st.runtime != nil {
					if err := st.runtime.checkSequenceLengthAttempted(len(out) + 1); err != nil {
						return nil, err
					}
				}
				out = append(out, collapse(v))
			}
		}
		return value.Array{Items: out}, nil
	case syntax.Block:
		return evalBlock(x, st)
	case syntax.Bind:
		v, _, err := evaluateBinding(x, st)
		return v, err
	case syntax.Lambda:
		return makeLambda(x, st), nil
	case syntax.Apply:
		return applyNode(x, st)
	case syntax.Placeholder:
		return placeholderValue{}, nil
	case syntax.Object:
		out := make(map[string]any, len(x.Pairs))
		order := make([]string, 0, len(x.Pairs))
		for _, pair := range x.Pairs {
			key := pair.Key
			if pair.KeyExpr == nil {
				if dynamic := field(st.current, pair.Key); !value.IsUndefined(dynamic) {
					dynamic = collapse(dynamic)
					if _, ok := dynamic.(string); !ok {
						return nil, runtimeError{
							code:     "T1003",
							msg:      "Key in object structure must evaluate to a string; got: " + toString(dynamic),
							value:    publicDiagnosticValue(dynamic),
							position: x.Pos.Offset + 1,
							hasPos:   true,
						}
					}
					key = dynamic.(string)
				}
			}
			if pair.KeyExpr != nil {
				keyState := st
				keyState.tail = false
				kv, e := eval(pair.KeyExpr, keyState)
				if e != nil {
					return nil, e
				}
				kv = collapse(kv)
				if containsUTF16String(kv) {
					return nil, unsupportedUTF16StringError()
				}
				if literal, ok := pair.KeyExpr.(syntax.Literal); !ok || literal.Kind != syntax.String {
					if _, ok := kv.(string); !ok {
						return nil, runtimeError{
							code:     "T1003",
							msg:      "Key in object structure must evaluate to a string; got: " + toString(kv),
							value:    publicDiagnosticValue(kv),
							position: x.Pos.Offset + 1,
							hasPos:   true,
						}
					}
				}
				key = toString(kv)
			}
			if err := validateObjectKey(key, pair.Pos); err != nil {
				return nil, err
			}
			if _, exists := out[key]; exists {
				return nil, runtimeError{code: "D1009", msg: "duplicate object key"}
			}
			valueState := st
			valueState.tail = false
			v, e := eval(pair.Value, valueState)
			if e != nil {
				return nil, e
			}
			if !value.IsUndefined(v) {
				if _, exists := out[key]; !exists {
					order = append(order, key)
				}
				out[key] = collapse(v)
			}
		}
		if st.preserveObjectOrder {
			return value.OrderedObject{Fields: out, Order: value.CanonicalObjectOrder(order)}, nil
		}
		return out, nil
	case syntax.Selector:
		baseState := st
		baseState.tail = false
		base, e := eval(x.Base, baseState)
		if e != nil {
			return nil, e
		}
		if c, ok := base.(contextual); ok {
			st.parent = c.parent
			st.vars = cloneVarsMutable(st.vars)
			for k, v := range c.vars {
				st.vars[k] = v
			}
		}
		result, e := selectValue(base, x.Index, st)
		if e != nil {
			return nil, e
		}
		return result, nil
	case syntax.Binary:
		result, err := binary(x.Op, x.Left, x.Right, st, x.Op == "." && implicitObjectProjection(x.Pos, x.Right))
		if err != nil {
			position := x.Pos.Offset + 1
			if x.Op == ".." {
				// The reference diagnostic points at the second dot in the
				// two-character range token.
				position++
			}
			return nil, withRuntimePosition(err, position)
		}
		return checkedSequenceResult(result, st.runtime)
	case syntax.Call:
		callState := st
		callState.tail = false
		fn, e := evalWithBindings(x.Function, callState)
		if e != nil {
			return nil, e
		}
		callState = stringArgumentState(callState, fn)
		args, partial, err := evaluateCallArgs(x.Args, callState)
		if err != nil {
			return nil, err
		}
		if _, ok := callable(fn); !ok {
			code := "T1008"
			if partial {
				if name, ok := x.Function.(syntax.Name); ok && knownBareBuiltin(name.Value) {
					code = "T1007"
				}
			} else if name, ok := x.Function.(syntax.Name); ok && knownBareBuiltin(name.Value) {
				// A bare builtin name is a field lookup, not a callable. The
				// reference implementation reports this distinct invocation
				// error rather than treating it like an arbitrary JSON value.
				code = "T1005"
			} else if _, isParent := x.Function.(syntax.Parent); isParent {
				code = "T1006"
			} else if _, literal := x.Function.(syntax.Literal); literal || value.IsUndefined(collapse(fn)) {
				code = "T1006"
			}
			message := "Attempted to invoke a non-function"
			if partial || x.Partial {
				message = "Attempted to partially apply a non-function"
			}
			return nil, withRuntimeCallMetadata(runtimeError{code: code, msg: message}, x, fn)
		}
		result, err := evaluateCall(st, fn, args, partial || x.Partial)
		if err != nil {
			return nil, withRuntimeCallMetadata(err, x, fn)
		}
		return checkedSequenceResult(result, st.runtime)
	case syntax.Unary:
		v, e := eval(x.Expr, st)
		if e != nil {
			return nil, e
		}
		if containsUTF16String(v) {
			return nil, unsupportedUTF16StringError()
		}
		switch x.Op {
		case "-":
			if value.IsUndefined(v) {
				return value.Undefined, nil
			}
			n, ok := arithmeticNumber(collapse(v))
			if !ok {
				return nil, runtimeError{code: "D1002", msg: "cannot negate a non-numeric value"}
			}
			return finiteResult(-n)
		case "+":
			if value.IsUndefined(v) {
				return value.Undefined, nil
			}
			n, ok := arithmeticNumber(collapse(v))
			if !ok {
				return nil, runtimeError{code: "D1002", msg: "cannot apply unary plus to a non-numeric value"}
			}
			return finiteResult(n)
		case "not":
			return !ebv(v), nil
		}
		return value.Undefined, nil
	case syntax.Path:
		// Compatibility with the Phase 1 AST shape.
		baseState := st
		baseState.tail = false
		v, e := eval(x.Base, baseState)
		if e != nil {
			return nil, e
		}
		for _, f := range x.Fields {
			v, e = applyPath(v, syntax.Name{Value: f.Value, Pos: f.Pos}, st, false)
			if e != nil {
				return nil, e
			}
		}
		return v, nil
	case syntax.Transform:
		return newTransformValue(x, st), nil
	default:
		return nil, fmt.Errorf("jsonata: unknown syntax node %T", n)
	}
}

func variableText(n syntax.Node) (string, bool) {
	switch x := n.(type) {
	case syntax.Name:
		return x.Value, true
	case syntax.Variable:
		return x.Name, true
	default:
		return "", false
	}
}
func stringArgumentState(st state, fn any) state {
	call, ok := callable(fn)
	if !ok {
		return st
	}
	switch call.callableName() {
	case "string":
		st.allowNonFinite = true
		st.preserveObjectOrder = true
	case "each", "keys", "merge", "sift", "spread":
		st.preserveObjectOrder = true
	}
	return st
}

func binary(op string, left, right syntax.Node, st state, groupObjects bool) (any, error) {
	if op == "%" {
		if _, parent := left.(syntax.Parent); parent {
			return nil, runtimeError{code: "T2001", msg: "expected a number"}
		}
		if _, parent := right.(syntax.Parent); parent {
			return nil, runtimeError{code: "T2001", msg: "expected a number"}
		}
	}
	if op == ";" {
		leftState := st
		leftState.tail = false
		if _, e := eval(left, leftState); e != nil {
			return nil, e
		}
		return eval(right, st)
	}
	if op == "." {
		leftState := st
		leftState.tail = false
		lv, e := eval(left, leftState)
		if e != nil {
			return nil, e
		}
		if literal, ok := left.(syntax.Literal); ok && literal.Kind == syntax.String {
			key, ok := literal.Value.(string)
			if !ok {
				return nil, unsupportedUTF16StringError()
			}
			resolved, err := fieldWithRuntime(st.current, key, st.runtime)
			if err != nil {
				return nil, err
			}
			if value.IsUndefined(resolved) {
				resolved, err = fieldWithRuntime(st.root, key, st.runtime)
				if err != nil {
					return nil, err
				}
			}
			if !value.IsUndefined(resolved) {
				lv = resolved
			}
		}
		if _, ok := left.(syntax.Name); ok && !value.IsUndefined(lv) {
			if _, alreadyContextual := lv.(contextual); !alreadyContextual {
				lv = contextual{v: lv, parent: frameFor(st.current, st), vars: cloneVars(st.vars)}
			}
		}
		if b, ok := lv.(bound); ok {
			ns := cloneVarsMutable(st.vars)
			for k, v := range b.vars {
				ns[k] = v
			}
			st.vars = ns
			lv = b.v
		}
		keep := false
		if a, ok := lv.(value.Array); ok {
			keep = a.Keep
		}
		result, e := applyPath(lv, right, st, groupObjects)
		if e != nil || !keep || value.IsUndefined(result) {
			return result, e
		}
		return value.Array{Items: items(collapse(result)), Keep: true}, nil
	}
	if op == "@" {
		leftState := st
		leftState.tail = false
		lv, e := eval(left, leftState)
		if e != nil {
			return nil, e
		}
		name, ok := variableText(right)
		if !ok {
			return value.Undefined, nil
		}
		return bindValues(lv, name, st, false)
	}
	if op == "#" {
		leftState := st
		leftState.tail = false
		lv, e := eval(left, leftState)
		if e != nil {
			return nil, e
		}
		name, ok := variableText(right)
		if !ok {
			return value.Undefined, nil
		}
		return bindValues(lv, name, st, true)
	}
	if op == "~>" {
		return applyNode(syntax.Apply{Left: left, Right: right}, st)
	}
	leftState := st
	leftState.tail = false
	lv, e := eval(left, leftState)
	if e != nil {
		return nil, e
	}
	if containsUTF16String(lv) {
		return nil, unsupportedUTF16StringError()
	}
	if op == "^" {
		if selector, ok := right.(syntax.Selector); ok {
			if binding, ok := selector.Base.(syntax.Binary); ok && binding.Op == "#" && selector.Index != nil {
				if name, ok := variableText(binding.Right); ok {
					sorted, err := binary("^", left, binding.Left, st, false)
					if err != nil {
						return nil, err
					}
					bound, err := bindValues(sorted, name, st, true)
					if err != nil {
						return nil, err
					}
					return selectValue(bound, selector.Index, st)
				}
			}
			if selector.Index == nil {
				if inner, ok := selector.Base.(syntax.Selector); ok && inner.Index != nil && isSortExpr(inner.Base) {
					sorted, err := binary("^", left, inner.Base, st, false)
					if err != nil {
						return nil, err
					}
					selected, err := selectValue(sorted, inner.Index, st)
					if err != nil {
						return nil, err
					}
					return selectValue(selected, nil, st)
				}
			}
		}
	}
	sortTarget := right
	var sortIndex syntax.Node
	if selector, ok := right.(syntax.Selector); ok && selector.Index != nil && isSortExpr(selector.Base) {
		sortTarget = selector.Base
		sortIndex = selector.Index
	}
	if op == "^" && isSortExpr(sortTarget) {
		values := items(lv)
		descending := false
		keyExpr := sortTarget
		if unary, ok := sortTarget.(syntax.Unary); ok && (unary.Op == ">" || unary.Op == "<") {
			descending = unary.Op == ">"
			keyExpr = unary.Expr
		}
		if len(values) <= 1 {
			return sortedSequence{values: lv, descending: descending, keep: sortedKeep(lv)}, nil
		}
		{
			type keyed struct {
				value, key any
				order      int
			}
			keys := make([]keyed, 0, len(values))
			for i, item := range values {
				original := item
				ns := st
				if b, ok := item.(bound); ok {
					for k, v := range b.vars {
						ns.vars = cloneVarsMutable(ns.vars)
						ns.vars[k] = v
					}
					item = b.v
				}
				if c, ok := item.(contextual); ok {
					ns.current, ns.parent = c.v, c.parent
					for k, v := range c.vars {
						ns.vars = cloneVarsMutable(ns.vars)
						ns.vars[k] = v
					}
					item = c.v
				}
				ns.current = item
				k, err := evalSortKey(keyExpr, ns)
				if err != nil {
					return nil, err
				}
				keys = append(keys, keyed{original, collapse(k), i})
			}
			hasStringKey := false
			hasNumericKey := false
			for _, item := range keys {
				if item.key == nil {
					return nil, runtimeError{code: "T2008", msg: "sort key must be a number"}
				}
				if value.IsUndefined(item.key) || sortKeyValid(item.key) {
					if _, ok := item.key.(string); ok {
						hasStringKey = true
					} else if _, ok := strictNumeric(item.key); ok {
						hasNumericKey = true
					}
					continue
				}
				if _, ok := strictNumeric(item.key); !ok {
					code := "T2008"
					if _, stringKey := item.key.(string); stringKey {
						code = "T2007"
					}
					return nil, runtimeError{code: code, msg: "sort key must be a number"}
				}
			}
			if hasStringKey && hasNumericKey {
				return nil, runtimeError{code: "T2007", msg: "sort key must be a number"}
			}
			sort.SliceStable(keys, func(i, j int) bool {
				if isSortNull(keys[i].key) || isSortNull(keys[j].key) {
					if isSortNull(keys[i].key) && isSortNull(keys[j].key) {
						return keys[i].order < keys[j].order
					}
					return !isSortNull(keys[i].key)
				}
				c := compareSortKey(keys[i].key, keys[j].key)
				if c == 0 {
					return keys[i].order < keys[j].order
				}
				if descending {
					return c > 0
				}
				return c < 0
			})
			out := make([]any, len(keys))
			for i, k := range keys {
				out[i] = k.value
			}
			result := any(sortedSequence{values: sequence(out), descending: descending, keep: sortedKeep(lv)})
			if sortIndex != nil {
				return selectValue(result, sortIndex, st)
			}
			return result, nil
		}
	}
	if op == "and" {
		if !ebv(lv) {
			return false, nil
		}
		rightState := st
		rightState.tail = false
		rv, e := eval(right, rightState)
		if e != nil {
			return nil, e
		}
		return ebv(rv), nil
	}
	if op == "or" {
		if ebv(lv) {
			return true, nil
		}
		rightState := st
		rightState.tail = false
		rv, e := eval(right, rightState)
		if e != nil {
			return nil, e
		}
		return ebv(rv), nil
	}
	if op == "?" {
		branchState := st
		branchState.tail = st.tail
		if branch, ok := right.(syntax.Binary); ok && branch.Op == ":" {
			if ebv(lv) {
				return eval(branch.Left, branchState)
			}
			return eval(branch.Right, branchState)
		}
		if !ebv(lv) {
			return value.Undefined, nil
		}
		return eval(right, branchState)
	}
	if op == "?:" {
		if defaultEBV(lv) {
			return lv, nil
		}
		return eval(right, st)
	}
	if op == "??" {
		if emptySequence(lv) {
			rightState := st
			rightState.tail = st.tail
			return eval(right, rightState)
		}
		return lv, nil
	}
	rightState := st
	rightState.tail = false
	rv, e := eval(right, rightState)
	if e != nil {
		return nil, e
	}
	if containsUTF16String(rv) {
		return nil, unsupportedUTF16StringError()
	}
	a, b := collapse(lv), collapse(rv)
	switch op {
	case "+":
		result, err := arithmetic(a, b, op, func(x, y float64) float64 { return x + y })
		return result, withRuntimeToken(err, op)
	case "-":
		result, err := arithmetic(a, b, op, func(x, y float64) float64 { return x - y })
		return result, withRuntimeToken(err, op)
	case "*":
		result, err := arithmetic(a, b, op, func(x, y float64) float64 { return x * y })
		return result, withRuntimeToken(err, op)
	case "/":
		if value.IsUndefined(a) || value.IsUndefined(b) {
			return value.Undefined, nil
		}
		x, ok := arithmeticNumber(a)
		y, okY := arithmeticNumber(b)
		if !ok || !okY {
			return nil, withRuntimeToken(arithmeticTypeError(a, b, "/"), op)
		}
		if y == 0 {
			if st.allowNonFinite {
				return nonFiniteNumber{value: x / y}, nil
			}
			return nil, withRuntimeToken(runtimeError{code: "T2002", msg: "division by zero"}, op)
		}
		return finiteResult(x / y)
	case "%":
		result, err := arithmetic(a, b, op, math.Mod)
		return result, withRuntimeToken(err, op)
	case "^":
		return arithmetic(a, b, op, math.Pow)
	case "&":
		return toString(a) + toString(b), nil
	case "..":
		result, err := numberRangeWithState(st, a, b)
		return result, withRuntimeToken(err, op)
	case "in":
		return contains(b, a), nil
	case "=":
		return equal(a, b), nil
	case "!=":
		return !equal(a, b), nil
	case "<":
		return compareChecked(a, b, "<", "T2009")
	case "<=":
		return compareChecked(a, b, "<=", "T2010")
	case ">":
		return compareChecked(a, b, ">", "T2010")
	case ">=":
		return compareChecked(a, b, ">=", "T2010")
	}
	return value.Undefined, nil
}

func isSortNull(v any) bool {
	return value.IsUndefined(v) || v == nil
}

func evalSortKey(n syntax.Node, st state) (any, error) {
	if array, ok := n.(syntax.Array); ok {
		out := make(sortTuple, 0, len(array.Items))
		for _, item := range array.Items {
			descending := false
			if unary, ok := item.(syntax.Unary); ok && (unary.Op == ">" || unary.Op == "<") {
				descending = unary.Op == ">"
				item = unary.Expr
			}
			v, err := eval(item, st)
			if err != nil {
				return nil, err
			}
			out = append(out, sortKeyPart{value: collapse(v), descending: descending})
		}
		return out, nil
	}
	v, err := eval(n, st)
	if err != nil {
		return nil, err
	}
	return collapse(v), nil
}

func compareSortKey(a, b any) int {
	if left, ok := a.(sortTuple); ok {
		right, ok := b.(sortTuple)
		if !ok {
			return compare(a, b)
		}
		for i := 0; i < len(left) && i < len(right); i++ {
			cmp := compare(left[i].value, right[i].value)
			if cmp != 0 {
				if left[i].descending {
					return -cmp
				}
				return cmp
			}
		}
		if len(left) < len(right) {
			return -1
		}
		if len(left) > len(right) {
			return 1
		}
		return 0
	}
	return compare(a, b)
}

func sortKeyValid(v any) bool {
	switch x := v.(type) {
	case sortTuple:
		for _, part := range x {
			if !sortKeyValid(part.value) && !value.IsUndefined(part.value) {
				return false
			}
		}
		return true
	case string:
		return true
	case []any:
		for _, item := range x {
			if !sortKeyTupleItemValid(item) && !value.IsUndefined(item) {
				return false
			}
		}
		return true
	case value.Array:
		for _, item := range x.Items {
			if !sortKeyTupleItemValid(item) && !value.IsUndefined(item) {
				return false
			}
		}
		return true
	case sequence:
		for _, item := range x {
			if !sortKeyTupleItemValid(item) && !value.IsUndefined(item) {
				return false
			}
		}
		return true
	default:
		_, ok := strictNumeric(v)
		return ok
	}
}

func sortKeyTupleItemValid(v any) bool {
	if _, ok := v.(string); ok {
		return true
	}
	return sortKeyValid(v)
}

func isSortExpr(n syntax.Node) bool {
	switch n.(type) {
	case syntax.Name, syntax.Variable, syntax.Binary, syntax.Unary, syntax.Array:
		return true
	default:
		return false
	}
}
func applyPath(base any, rhs syntax.Node, st state, groupObjects bool) (any, error) {
	if selector, ok := rhs.(syntax.Selector); ok {
		if local, post, split := splitJoinSelectors(selector); split {
			joined, err := applyPath(base, local, st, false)
			if err != nil {
				return nil, err
			}
			for _, index := range post {
				joined, err = selectValue(joined, index, st)
				if err != nil {
					return nil, err
				}
			}
			return joined, nil
		}
	}
	if binding, ok := rhs.(syntax.Binary); ok && binding.Op == "#" {
		if selector, ok := binding.Left.(syntax.Selector); ok && selectorStartsJoin(selector) {
			joined, err := applyPath(base, selector, st, false)
			if err != nil {
				return nil, err
			}
			name, ok := variableText(binding.Right)
			if !ok {
				return value.Undefined, nil
			}
			return bindValues(joined, name, st, true)
		}
	}
	if groupObjects {
		if object, ok := rhs.(syntax.Object); ok {
			if _, dynamic := dynamicObjectProjection(object); dynamic {
				return groupedObjectProjection(base, object, st)
			}
		}
		if path, ok := rhs.(syntax.Binary); ok && path.Op == "." {
			if object, ok := path.Right.(syntax.Object); ok {
				if _, dynamic := dynamicObjectProjection(object); dynamic {
					target, err := applyPath(base, path.Left, st, false)
					if err != nil {
						return nil, err
					}
					return groupedObjectProjection(target, object, st)
				}
			}
		}
	}
	out := make([]any, 0, sequenceAllocationCapacity(itemsLength(base), st.runtime))
	baseCollection := false
	baseSequence := false
	switch x := base.(type) {
	case value.Array, []any:
		baseCollection = true
	case sequence:
		baseCollection = true
		baseSequence = true
	case contextual:
		switch x.v.(type) {
		case value.Array, []any:
			baseCollection = true
		case sequence:
			baseCollection = true
			baseSequence = true
		}
	}
	for index, raw := range items(base) {
		source := frameFor(raw, st)
		item := source.v
		vars := cloneVarsMutable(source.vars)
		ns := st
		ns.tail = false
		ns.parent = source.parent
		ns.current = item
		ns.vars = vars
		ns.vars["#"] = index
		if nested, ok := rhs.(syntax.Binary); ok && nested.Op == "." {
			ns.parent = source
		}
		// A quoted path segment is lexed as a string literal, but in path
		// position it names a field rather than producing the literal value.
		var v any
		var e error
		if lit, ok := rhs.(syntax.Literal); ok && lit.Kind == syntax.String {
			key, ok := lit.Value.(string)
			if !ok {
				return nil, unsupportedUTF16StringError()
			}
			v, e = fieldWithRuntime(ns.current, key, st.runtime)
		} else {
			v, e = eval(rhs, ns)
		}
		if e != nil {
			return nil, e
		}
		vals := make([]any, 0)
		if arrayProjection, parenthesizedArray := rhs.(syntax.Array); parenthesizedArray && arrayProjection.FlattenInPath {
			if a, ok := v.(value.Array); ok {
				for _, item := range a.Items {
					if err := pathFlatten(item, &vals, st.runtime); err != nil {
						return nil, err
					}
				}
			} else if err := pathFlatten(v, &vals, st.runtime); err != nil {
				return nil, err
			}
		} else if _, blockProjection := rhs.(syntax.Block); blockProjection {
			if a, ok := v.(value.Array); ok {
				for _, item := range a.Items {
					if err := pathFlatten(item, &vals, st.runtime); err != nil {
						return nil, err
					}
				}
			} else if err := pathFlatten(v, &vals, st.runtime); err != nil {
				return nil, err
			}
		} else if _, isArrayProjection := rhs.(syntax.Array); isArrayProjection && baseSequence && arrayUsesParent(rhs) {
			if a, ok := v.(value.Array); ok {
				for _, item := range a.Items {
					if err := pathFlatten(item, &vals, st.runtime); err != nil {
						return nil, err
					}
				}
			} else {
				if err := pathFlatten(v, &vals, st.runtime); err != nil {
					return nil, err
				}
			}
		} else if selector, isArrayProjection := rhs.(syntax.Selector); isArrayProjection && selector.Index == nil && baseSequence {
			if _, explicitArray := selector.Base.(syntax.Array); explicitArray {
				if a, ok := v.(value.Array); ok {
					for _, item := range a.Items {
						if err := pathFlatten(item, &vals, st.runtime); err != nil {
							return nil, err
						}
					}
				} else {
					if err := pathFlatten(v, &vals, st.runtime); err != nil {
						return nil, err
					}
				}
			} else {
				if err := pathFlatten(v, &vals, st.runtime); err != nil {
					return nil, err
				}
			}
		} else if isVariableOrName(rhs) && baseCollection {
			if a, ok := v.(value.Array); ok && !a.Keep {
				if st.runtime != nil {
					if err := st.runtime.checkSequenceLength(len(vals) + len(a.Items)); err != nil {
						return nil, err
					}
				}
				vals = append(vals, a.Items...)
			} else {
				if err := pathFlatten(v, &vals, st.runtime); err != nil {
					return nil, err
				}
			}
		} else {
			if err := pathFlatten(v, &vals, st.runtime); err != nil {
				return nil, err
			}
		}
		for _, val := range vals {
			if st.runtime != nil {
				if err := st.runtime.checkSequenceLength(len(out) + 1); err != nil {
					return nil, err
				}
			}
			valueState := ns
			valueState.parent = source
			out = append(out, frameFor(val, valueState))
		}
	}
	if len(out) == 0 {
		if groupObjects {
			return map[string]any{}, nil
		}
		return value.Undefined, nil
	}
	if groupObjects {
		_, dynamicKeys := dynamicObjectProjection(rhs)
		if !dynamicKeys {
			return pathResult(out, rhs, st.runtime)
		}
		grouped := make(map[string]any)
		for _, item := range out {
			m, ok := collapse(item).(map[string]any)
			if !ok {
				continue
			}
			for key, value := range m {
				if previous, exists := grouped[key]; exists {
					groupedValue, err := appendGrouped(previous, value, st.runtime)
					if err != nil {
						return nil, err
					}
					grouped[key] = groupedValue
				} else {
					grouped[key] = value
				}
			}
		}
		return normalizeGrouped(grouped).(map[string]any), nil
	}
	return pathResult(out, rhs, st.runtime)
}

func selectorStartsJoin(selector syntax.Selector) bool {
	current := selector.Base
	for {
		binding, ok := current.(syntax.Binary)
		if !ok {
			return false
		}
		if binding.Op == "@" {
			return true
		}
		if binding.Op != "#" {
			return false
		}
		current = binding.Left
	}
}

func splitJoinSelectors(selector syntax.Selector) (syntax.Selector, []syntax.Node, bool) {
	chain := []syntax.Selector{selector}
	current := selector
	for {
		inner, ok := current.Base.(syntax.Selector)
		if !ok {
			break
		}
		chain = append(chain, inner)
		current = inner
	}
	if len(chain) < 2 || !selectorStartsJoin(current) {
		return syntax.Selector{}, nil, false
	}
	post := make([]syntax.Node, 0, len(chain)-1)
	for index := len(chain) - 2; index >= 0; index-- {
		post = append(post, chain[index].Index)
	}
	return current, post, true
}

// groupedObjectProjection evaluates each dynamic object key against the
// complete sequence contributing that key. JSONata evaluates object values
// after grouping the input by a dynamic key, which matters for aggregations
// such as $join and for selectors such as (Price)[0]. Evaluating the object
// once per input item would turn both into ordinary duplicate-key arrays.
func groupedObjectProjection(base any, object syntax.Object, st state) (any, error) {
	rawItems := items(base)
	if len(rawItems) == 0 {
		return map[string]any{}, nil
	}
	if st.runtime != nil {
		if err := st.runtime.checkSequenceLength(len(rawItems)); err != nil {
			return nil, err
		}
	}
	frames := make([]contextual, len(rawItems))
	for index, raw := range rawItems {
		frames[index] = frameFor(raw, st)
	}
	projectionKeys := make([][]string, len(object.Pairs))
	orderedKeys := make([]string, 0, len(frames)*len(object.Pairs))
	seenOrderedKeys := make(map[string]struct{}, len(frames)*len(object.Pairs))
	for frameIndex, frame := range frames {
		for pairIndex, pair := range object.Pairs {
			key, err := objectPairKey(pair)
			if err != nil {
				return nil, err
			}
			if dynamicObjectPair(pair) {
				if projectionKeys[pairIndex] == nil {
					projectionKeys[pairIndex] = make([]string, len(frames))
				}
				var err error
				key, err = evalDynamicObjectKey(pair, frame, frameIndex, st)
				if err != nil {
					return nil, err
				}
				projectionKeys[pairIndex][frameIndex] = key
			}
			if err := validateObjectKey(key, pair.Pos); err != nil {
				return nil, err
			}
			if _, exists := seenOrderedKeys[key]; !exists {
				seenOrderedKeys[key] = struct{}{}
				orderedKeys = append(orderedKeys, key)
			}
		}
	}
	result := make(map[string]any, len(object.Pairs))
	for pairIndex, pair := range object.Pairs {
		if !dynamicObjectPair(pair) {
			if st.runtime != nil {
				if err := st.runtime.checkSequenceLengthAttempted(len(frames)); err != nil {
					return nil, err
				}
			}
			v, err := evalObjectPairValue(pair, groupedProjectionState(frames, st))
			if err != nil {
				return nil, err
			}
			if !value.IsUndefined(v) {
				key, err := objectPairKey(pair)
				if err != nil {
					return nil, err
				}
				if _, exists := result[key]; exists {
					return nil, runtimeError{code: "D1009", msg: "duplicate object key"}
				}
				result[key] = normalizeProjectionValue(v)
			}
			continue
		}

		groups := make(map[string][]contextual)
		order := make([]string, 0, len(frames))
		for index, frame := range frames {
			key := projectionKeys[pairIndex][index]
			if _, exists := groups[key]; !exists {
				order = append(order, key)
			}
			if st.runtime != nil && len(groups[key]) > 0 {
				if err := st.runtime.checkSequenceLengthAttempted(len(groups[key]) + 1); err != nil {
					return nil, err
				}
			}
			groups[key] = append(groups[key], frame)
		}
		for _, key := range order {
			group := groups[key]
			v, err := evalObjectPairValue(pair, groupedProjectionState(group, st))
			if err != nil {
				return nil, err
			}
			if value.IsUndefined(v) {
				continue
			}
			v = normalizeProjectionValue(v)
			if _, exists := result[key]; exists {
				return nil, runtimeError{code: "D1009", msg: "duplicate object key"}
			}
			result[key] = collapse(v)
		}
	}
	if st.preserveObjectOrder {
		resultOrder := make([]string, 0, len(result))
		for _, key := range orderedKeys {
			if _, exists := result[key]; exists {
				resultOrder = append(resultOrder, key)
			}
		}
		return value.OrderedObject{Fields: result, Order: value.CanonicalObjectOrder(resultOrder)}, nil
	}
	return result, nil
}

func normalizeProjectionValue(v any) any {
	switch x := v.(type) {
	case sequence:
		return flattenProjectionSequence(x)
	case []any:
		return flattenProjectionSequence(x)
	default:
		return collapse(v)
	}
}

func flattenProjectionSequence(values []any) any {
	out := make([]any, 0, len(values))
	for _, item := range values {
		if contextualItem, ok := item.(contextual); ok {
			item = contextualItem.v
		}
		if boundItem, ok := item.(bound); ok {
			item = boundItem.v
		}
		switch nested := item.(type) {
		case value.Array:
			for _, child := range nested.Items {
				out = append(out, collapse(child))
			}
		case sequence:
			for _, child := range nested {
				out = append(out, collapse(child))
			}
		case []any:
			out = append(out, nested...)
		default:
			out = append(out, collapse(item))
		}
	}
	return out
}

func dynamicObjectPair(pair syntax.Pair) bool {
	if pair.KeyExpr == nil {
		return pair.Key != ""
	}
	literal, ok := pair.KeyExpr.(syntax.Literal)
	return !ok || literal.Kind != syntax.String
}

func objectPairKey(pair syntax.Pair) (string, error) {
	if pair.KeyExpr == nil {
		return pair.Key, nil
	}
	literal, ok := pair.KeyExpr.(syntax.Literal)
	if ok && literal.Kind == syntax.String {
		key, ok := literal.Value.(string)
		if !ok {
			return "", unsupportedUTF16StringError()
		}
		return key, nil
	}
	return pair.Key, nil
}

func groupedProjectionState(frames []contextual, st state) state {
	grouped := make([]any, len(frames))
	for index, frame := range frames {
		grouped[index] = frame
	}
	current := any(sequence(grouped))
	if len(frames) == 1 {
		current = frames[0]
	}
	groupState := st
	groupState.current = current
	groupState.parent = frames[0].parent
	groupState.vars = cloneVarsMutable(st.vars)
	keys := make(map[string]struct{})
	for _, frame := range frames {
		for key := range frame.vars {
			keys[key] = struct{}{}
		}
	}
	for key := range keys {
		values := make([]any, 0, len(frames))
		allEqual := true
		for index, frame := range frames {
			item, ok := frame.vars[key]
			if !ok {
				allEqual = false
				continue
			}
			values = append(values, item)
			if index > 0 && !equal(values[0], item) {
				allEqual = false
			}
		}
		if len(values) == 0 {
			continue
		}
		if allEqual {
			groupState.vars[key] = values[0]
		} else if len(values) == 1 {
			groupState.vars[key] = values[0]
		} else {
			groupState.vars[key] = sequence(values)
		}
	}
	groupState.tail = false
	return groupState
}

func evalObjectPairValue(pair syntax.Pair, groupState state) (any, error) {
	return eval(pair.Value, groupState)
}

func evalDynamicObjectKey(pair syntax.Pair, frame contextual, index int, st state) (string, error) {
	keyState := st
	keyState.current = frame.v
	keyState.parent = frame.parent
	keyState.vars = cloneVarsMutable(frame.vars)
	keyState.vars["#"] = index
	keyState.tail = false
	var keyValue any
	var err error
	if pair.KeyExpr == nil {
		keyValue = field(keyState.current, pair.Key)
	} else {
		keyValue, err = eval(pair.KeyExpr, keyState)
		if err != nil {
			return "", err
		}
	}
	keyValue = collapse(keyValue)
	key, ok := keyValue.(string)
	if !ok {
		return "", runtimeError{
			code:     "T1003",
			msg:      "Key in object structure must evaluate to a string; got: " + toString(keyValue),
			value:    publicDiagnosticValue(keyValue),
			position: pair.Pos.Offset + 1,
			hasPos:   true,
		}
	}
	return key, nil
}

func isVariableOrName(n syntax.Node) bool {
	switch n.(type) {
	case syntax.Name, syntax.Variable:
		return true
	default:
		return false
	}
}

func pathResult(out []any, rhs syntax.Node, runtime *evalRuntime) (any, error) {
	if runtime != nil {
		if err := runtime.checkSequenceLength(len(out)); err != nil {
			return nil, err
		}
	}
	if len(out) == 1 {
		if selector, ok := rhs.(syntax.Selector); ok && selector.Index == nil {
			if _, explicitArray := selector.Base.(syntax.Array); explicitArray {
				return value.Array{Items: []any{out[0]}, Keep: true}, nil
			}
		}
		return out[0], nil
	}
	return sequence(out), nil
}

func implicitObjectProjection(pos syntax.Position, rhs syntax.Node) bool {
	if binary, ok := rhs.(syntax.Binary); ok && binary.Op == "." {
		if object, ok := binary.Right.(syntax.Object); ok {
			return object.Pos.Offset == binary.Pos.Offset
		}
		return implicitObjectProjection(binary.Pos, binary.Right)
	}
	object, ok := rhs.(syntax.Object)
	return ok && object.Pos.Offset == pos.Offset
}

func isPathArray(v any) bool {
	a, ok := v.(value.Array)
	return ok && !a.Keep
}

func arrayUsesParent(n syntax.Node) bool {
	switch x := n.(type) {
	case syntax.Parent:
		return true
	case syntax.Array:
		for _, item := range x.Items {
			if arrayUsesParent(item) {
				return true
			}
		}
	case syntax.Binary:
		return arrayUsesParent(x.Left) || arrayUsesParent(x.Right)
	case syntax.Selector:
		return arrayUsesParent(x.Base) || arrayUsesParent(x.Index)
	case syntax.Unary:
		return arrayUsesParent(x.Expr)
	}
	return false
}

func dynamicObjectProjection(n syntax.Node) (bool, bool) {
	if binary, ok := n.(syntax.Binary); ok && binary.Op == "." {
		if object, dynamic := dynamicObjectProjection(binary.Right); object {
			return true, dynamic
		}
	}
	o, ok := n.(syntax.Object)
	if !ok {
		return false, false
	}
	dynamic := false
	for _, pair := range o.Pairs {
		if pair.KeyExpr == nil {
			dynamic = pair.Key != ""
		} else {
			if literal, ok := pair.KeyExpr.(syntax.Literal); !ok || literal.Kind != syntax.String {
				dynamic = true
			}
		}
	}
	return true, dynamic
}

func appendGrouped(previous, next any, runtime *evalRuntime) (any, error) {
	if _, stringValue := collapse(previous).(string); stringValue && equal(previous, next) {
		return previous, nil
	}
	values := make([]any, 0)
	descending := false
	sorted := false
	values = flattenGroupedSorted(values, previous, &sorted, &descending)
	values = flattenGroupedSorted(values, next, &sorted, &descending)
	if runtime != nil {
		if err := runtime.checkSequenceLengthAttempted(len(values)); err != nil {
			return nil, err
		}
	}
	if sorted {
		sort.SliceStable(values, func(i, j int) bool {
			cmp := compare(values[i], values[j])
			if descending {
				return cmp > 0
			}
			return cmp < 0
		})
	}
	if len(values) == 1 {
		return values[0], nil
	}
	return sequence(values), nil
}

func flattenGroupedSorted(dst []any, v any, sorted *bool, descending *bool) []any {
	if x, ok := v.(sortedSequence); ok {
		*sorted = true
		*descending = x.descending
		return flattenGroupedSorted(dst, x.values, sorted, descending)
	}
	switch x := v.(type) {
	case sequence:
		for _, item := range x {
			dst = flattenGroupedSorted(dst, item, sorted, descending)
		}
	case []any:
		for _, item := range x {
			dst = flattenGroupedSorted(dst, item, sorted, descending)
		}
	case value.Array:
		for _, item := range x.Items {
			dst = flattenGroupedSorted(dst, item, sorted, descending)
		}
	default:
		if !value.IsUndefined(v) {
			dst = append(dst, v)
		}
	}
	return dst
}

func normalizeGrouped(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			if array, ok := item.(value.Array); ok && len(array.Items) == 1 {
				out[i] = normalizeGrouped(array.Items[0])
				continue
			}
			out[i] = normalizeGrouped(item)
		}
		return out
	case map[string]any:
		for key, item := range x {
			x[key] = normalizeGrouped(item)
		}
	}
	return v
}

func flattenGrouped(dst []any, v any) []any {
	switch x := v.(type) {
	case sequence:
		for _, item := range x {
			dst = flattenGrouped(dst, item)
		}
	case []any:
		for _, item := range x {
			dst = flattenGrouped(dst, item)
		}
	case value.Array:
		for _, item := range x.Items {
			dst = flattenGrouped(dst, item)
		}
	default:
		if !value.IsUndefined(v) {
			dst = append(dst, v)
		}
	}
	return dst
}

func pathFlatten(v any, out *[]any, runtime *evalRuntime) error {
	if value.IsUndefined(v) {
		return nil
	}
	switch x := v.(type) {
	case sequence:
		for _, item := range x {
			if err := pathFlatten(item, out, runtime); err != nil {
				return err
			}
		}
	case value.Array:
		if len(x.Items) == 0 && !x.Keep {
			return nil
		}
		if runtime != nil {
			if err := runtime.checkSequenceLength(len(*out) + 1); err != nil {
				return err
			}
		}
		*out = append(*out, v)
	default:
		if runtime != nil {
			if err := runtime.checkSequenceLength(len(*out) + 1); err != nil {
				return err
			}
		}
		*out = append(*out, v)
	}
	return nil
}
func selectValue(base any, idx syntax.Node, st state) (any, error) {
	baseKeep := false
	if a, ok := base.(value.Array); ok {
		baseKeep = a.Keep
	}
	if a, ok := base.(sortedSequence); ok {
		baseKeep = a.keep
	}
	var contextualBase any
	if c, ok := base.(contextual); ok {
		contextualBase = c.v
	} else {
		contextualBase = base
	}
	arr := items(contextualBase)
	var container any = frameFor(st.current, st)
	if contextualValue, ok := base.(contextual); ok && contextualValue.parent != nil {
		container = contextualValue.parent
		if contextualValue.lineage {
			container = repeatedLineageFrame(container)
		}
	}
	if b, ok := base.(bound); ok {
		arr = []any{b}
	}
	if idx == nil {
		// [] is an explicit array constructor. A contextual array is one
		// projected value and must stay grouped; a direct input array is
		// selected element-wise.
		if _, ok := base.(contextual); ok {
			return value.Array{Items: []any{base}, Keep: true}, nil
		}
		return value.Array{Items: arr, Keep: true}, nil
	}
	var iv any
	if !indexUsesCurrent(idx) {
		var e error
		iv, e = eval(idx, st)
		if e != nil {
			return nil, e
		}
		iv = collapse(iv)
	}
	if s, ok := iv.(sequence); ok {
		iv = collapse(s)
	}
	if n, ok := numeric(iv); ok {
		i := int(n)
		if i < 0 {
			i = len(arr) + i
		}
		if i < 0 || i >= len(arr) {
			return value.Undefined, nil
		}
		selectedState := st
		selectedState.parent = container
		selected := frameFor(arr[i], selectedState)
		if baseKeep {
			return value.Array{Items: []any{selected}, Keep: true}, nil
		}
		return selected, nil
	}
	if indices := items(iv); len(indices) > 0 {
		allNumeric := true
		wanted := make(map[int]struct{}, len(indices))
		for _, raw := range indices {
			n, ok := numeric(collapse(raw))
			if !ok {
				allNumeric = false
				break
			}
			i := int(n)
			if i < 0 {
				i = len(arr) + i
			}
			if i >= 0 && i < len(arr) {
				wanted[i] = struct{}{}
			}
		}
		if allNumeric {
			selected := make([]any, 0, sequenceAllocationCapacity(len(wanted), st.runtime))
			for i, item := range arr {
				if _, ok := wanted[i]; ok {
					if st.runtime != nil {
						if err := st.runtime.checkSequenceLength(len(selected) + 1); err != nil {
							return nil, err
						}
					}
					selectedState := st
					selectedState.parent = container
					selected = append(selected, frameFor(item, selectedState))
				}
			}
			if len(selected) == 0 {
				return value.Undefined, nil
			}
			if len(selected) == 1 {
				if baseKeep {
					return value.Array{Items: []any{selected[0]}, Keep: true}, nil
				}
				return selected[0], nil
			}
			if baseKeep {
				return value.Array{Items: selected, Keep: true}, nil
			}
			return sequence(selected), nil
		}
	}
	out := make([]any, 0, sequenceAllocationCapacity(len(arr), st.runtime))
	for i, item := range arr {
		ns := st
		ns.tail = false
		ns.parent = container
		if c, ok := item.(contextual); ok {
			ns.current = c.v
			ns.parent = c.parent
			ns.vars = cloneVarsMutable(st.vars)
			for k, v := range c.vars {
				ns.vars[k] = v
			}
		} else if b, ok := item.(bound); ok {
			ns.current = b.v
			ns.vars = cloneVarsMutable(st.vars)
			for k, v := range b.vars {
				ns.vars[k] = v
			}
		} else {
			ns.current = item
			ns.vars = cloneVarsMutable(st.vars)
		}
		ns.vars["#"] = i
		v, e := eval(idx, ns)
		if e != nil {
			return nil, e
		}
		if ebv(v) {
			if st.runtime != nil {
				if err := st.runtime.checkSequenceLength(len(out) + 1); err != nil {
					return nil, err
				}
			}
			if c, ok := item.(contextual); ok {
				out = append(out, contextual{v: c.v, parent: container, vars: ns.vars})
			} else if b, ok := item.(bound); ok {
				out = append(out, contextual{v: b.v, parent: container, vars: ns.vars})
			} else {
				out = append(out, contextual{v: item, parent: container, vars: ns.vars})
			}
		}
	}
	if len(out) == 0 {
		return value.Undefined, nil
	}
	if len(out) == 1 {
		if baseKeep {
			return value.Array{Items: out, Keep: true}, nil
		}
		return out[0], nil
	}
	if baseKeep {
		return value.Array{Items: out, Keep: true}, nil
	}
	return sequence(out), nil
}

func isStaticIndex(n syntax.Node) bool {
	switch x := n.(type) {
	case syntax.Literal:
		return x.Kind == syntax.Number
	case syntax.Array:
		for _, item := range x.Items {
			if !isStaticIndex(item) {
				return false
			}
		}
		return true
	case syntax.Unary:
		return isStaticIndex(x.Expr)
	case syntax.Binary:
		return isStaticIndex(x.Left) && isStaticIndex(x.Right)
	default:
		return false
	}
}

func indexUsesCurrent(n syntax.Node) bool {
	switch x := n.(type) {
	case syntax.Name:
		return x.Value == "$" || x.Value == "%"
	case syntax.Variable:
		return x.Name == "$" || x.Name == "%"
	case syntax.Parent:
		return true
	case syntax.Binary:
		return indexUsesCurrent(x.Left) || indexUsesCurrent(x.Right)
	case syntax.Unary:
		return indexUsesCurrent(x.Expr)
	case syntax.Array:
		for _, item := range x.Items {
			if indexUsesCurrent(item) {
				return true
			}
		}
	case syntax.Selector:
		return indexUsesCurrent(x.Base) || indexUsesCurrent(x.Index)
	case syntax.Object:
		for _, pair := range x.Pairs {
			if indexUsesCurrent(pair.KeyExpr) || indexUsesCurrent(pair.Value) {
				return true
			}
		}
	case syntax.Call:
		if indexUsesCurrent(x.Function) {
			return true
		}
		for _, arg := range x.Args {
			if indexUsesCurrent(arg) {
				return true
			}
		}
	}
	return false
}
func wildcard(v any, recursive bool, runtime *evalRuntime) (any, error) {
	if c, ok := v.(contextual); ok {
		v = c.v
	}
	if recursive {
		out := []any{}
		var walk func(any) error
		walk = func(x any) error {
			switch y := x.(type) {
			case map[string]any:
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + 1); err != nil {
						return err
					}
				}
				out = append(out, y)
				keys := make([]string, 0, len(y))
				for k := range y {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					if err := walk(y[k]); err != nil {
						return err
					}
				}
			case value.OrderedObject:
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + 1); err != nil {
						return err
					}
				}
				out = append(out, y)
				for _, key := range y.Order {
					if err := walk(y.Fields[key]); err != nil {
						return err
					}
				}
			case []any:
				for _, item := range y {
					if err := walk(item); err != nil {
						return err
					}
				}
			case value.Array:
				for _, item := range y.Items {
					if err := walk(item); err != nil {
						return err
					}
				}
			case sequence:
				for _, item := range y {
					if err := walk(item); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := walk(v); err != nil {
			return nil, err
		}
		return sequence(out), nil
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, 0, sequenceAllocationCapacity(len(keys), runtime))
		for _, k := range keys {
			additional := 1
			if a, ok := x[k].([]any); ok {
				additional = len(a)
				if runtime != nil {
					if err := runtime.checkSequenceLengthAttempted(len(out) + additional); err != nil {
						return nil, err
					}
				}
				out = append(out, a...)
			} else if a, ok := x[k].(value.Array); ok {
				additional = len(a.Items)
				if runtime != nil {
					if err := runtime.checkSequenceLengthAttempted(len(out) + additional); err != nil {
						return nil, err
					}
				}
				out = append(out, a.Items...)
			} else {
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + additional); err != nil {
						return nil, err
					}
				}
				out = append(out, x[k])
			}
		}
		return sequence(out), nil
	case value.OrderedObject:
		out := make([]any, 0, sequenceAllocationCapacity(len(x.Order), runtime))
		for _, key := range x.Order {
			if a, ok := x.Fields[key].([]any); ok {
				if runtime != nil {
					if err := runtime.checkSequenceLengthAttempted(len(out) + len(a)); err != nil {
						return nil, err
					}
				}
				out = append(out, a...)
			} else if a, ok := x.Fields[key].(value.Array); ok {
				if runtime != nil {
					if err := runtime.checkSequenceLengthAttempted(len(out) + len(a.Items)); err != nil {
						return nil, err
					}
				}
				out = append(out, a.Items...)
			} else {
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + 1); err != nil {
						return nil, err
					}
				}
				out = append(out, x.Fields[key])
			}
		}
		return sequence(out), nil
	case []any:
		if runtime != nil {
			if err := runtime.checkSequenceLength(len(x)); err != nil {
				return nil, err
			}
		}
		return sequence(x), nil
	case value.Array:
		if runtime != nil {
			if err := runtime.checkSequenceLength(len(x.Items)); err != nil {
				return nil, err
			}
		}
		return sequence(x.Items), nil
	default:
		return value.Undefined, nil
	}
}

func lineageField(parent any, name string, runtime *evalRuntime) (any, error) {
	for current := parent; current != nil; {
		if runtime != nil {
			if err := runtime.check(); err != nil {
				return nil, err
			}
		}
		switch frame := current.(type) {
		case contextual:
			candidate, err := fieldWithRuntime(frame.v, name, runtime)
			if err != nil {
				return nil, err
			}
			if !value.IsUndefined(candidate) {
				return contextual{v: candidate, parent: frame, vars: cloneVars(frame.vars), lineage: true}, nil
			}
			current = frame.parent
		case *contextual:
			if frame == nil {
				return value.Undefined, nil
			}
			candidate, err := fieldWithRuntime(frame.v, name, runtime)
			if err != nil {
				return nil, err
			}
			if !value.IsUndefined(candidate) {
				return contextual{v: candidate, parent: *frame, vars: cloneVars(frame.vars), lineage: true}, nil
			}
			current = frame.parent
		default:
			candidate, err := fieldWithRuntime(current, name, runtime)
			if err != nil {
				return nil, err
			}
			if !value.IsUndefined(candidate) {
				return contextual{v: candidate, parent: frameFor(current, state{}), vars: map[string]any{}, lineage: true}, nil
			}
			return value.Undefined, nil
		}
	}
	return value.Undefined, nil
}

func hasLineageBindings(vars map[string]any) bool {
	for _, item := range vars {
		switch item.(type) {
		case contextual, *contextual, bound:
			return true
		}
	}
	return false
}

func repeatedLineageFrame(parent any) any {
	switch frame := parent.(type) {
	case contextual:
		return contextual{v: frame.v, parent: frame, vars: cloneVars(frame.vars)}
	case *contextual:
		if frame != nil {
			return contextual{v: frame.v, parent: *frame, vars: cloneVars(frame.vars)}
		}
	}
	return parent
}

func inheritLineageVars(v any, vars map[string]any) any {
	frame, ok := v.(contextual)
	if !ok {
		return v
	}
	merged := cloneVarsMutable(frame.vars)
	for key, item := range vars {
		merged[key] = item
	}
	frame.vars = merged
	return frame
}

func field(v any, name string) any {
	result, _ := fieldWithRuntime(v, name, nil)
	return result
}

func fieldWithRuntime(v any, name string, runtime *evalRuntime) (any, error) {
	if b, ok := v.(bound); ok {
		v = b.v
	}
	if c, ok := v.(contextual); ok {
		v = c.v
	}
	if value.IsUndefined(v) || v == nil {
		return value.Undefined, nil
	}
	if s, ok := v.(sequence); ok {
		out := []any{}
		for _, i := range s {
			child, err := fieldWithRuntime(i, name, runtime)
			if err != nil {
				return nil, err
			}
			out, err = appendFlattenedSequence(out, child, runtime)
			if err != nil {
				return nil, err
			}
		}
		if len(out) == 0 {
			return value.Undefined, nil
		}
		if len(out) == 1 {
			return out[0], nil
		}
		return sequence(out), nil
	}
	switch x := v.(type) {
	case map[string]any:
		if y, ok := x[name]; ok {
			return y, nil
		}
		return value.Undefined, nil
	case value.OrderedObject:
		if y, ok := x.Fields[name]; ok {
			return y, nil
		}
		return value.Undefined, nil
	case []any:
		out := []any{}
		for _, i := range x {
			child, err := fieldWithRuntime(i, name, runtime)
			if err != nil {
				return nil, err
			}
			// A field projection over an input array flattens the sequence
			// contributed by each item by one array level. Keep nested arrays
			// intact so explicit array constructors remain grouped.
			if s, ok := child.(sequence); ok {
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + len(s)); err != nil {
						return nil, err
					}
				}
				out = append(out, s...)
			} else if a, ok := child.([]any); ok {
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + len(a)); err != nil {
						return nil, err
					}
				}
				out = append(out, a...)
			} else if !value.IsUndefined(child) {
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + 1); err != nil {
						return nil, err
					}
				}
				out = append(out, child)
			}
		}
		if len(out) == 0 {
			return value.Undefined, nil
		}
		if len(out) == 1 {
			return out[0], nil
		}
		return sequence(out), nil
	case value.Array:
		out := []any{}
		for _, item := range x.Items {
			child, err := fieldWithRuntime(item, name, runtime)
			if err != nil {
				return nil, err
			}
			if s, ok := child.(sequence); ok {
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + len(s)); err != nil {
						return nil, err
					}
				}
				out = append(out, s...)
			} else if a, ok := child.(value.Array); ok {
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + len(a.Items)); err != nil {
						return nil, err
					}
				}
				out = append(out, a.Items...)
			} else if !value.IsUndefined(child) {
				if runtime != nil {
					if err := runtime.checkSequenceLength(len(out) + 1); err != nil {
						return nil, err
					}
				}
				out = append(out, child)
			}
		}
		if len(out) == 0 {
			return value.Undefined, nil
		}
		return sequence(out), nil
	}
	r := reflect.ValueOf(v)
	for r.IsValid() && (r.Kind() == reflect.Pointer || r.Kind() == reflect.Interface) {
		if r.IsNil() {
			return value.Undefined, nil
		}
		r = r.Elem()
	}
	if r.IsValid() && r.Kind() == reflect.Struct {
		for i := 0; i < r.NumField(); i++ {
			f := r.Type().Field(i)
			if f.PkgPath != "" {
				continue
			}
			jn := f.Name
			if tag := f.Tag.Get("json"); tag != "" {
				if tag == "-" {
					continue
				}
				if k := strings.IndexByte(tag, ','); k >= 0 {
					tag = tag[:k]
				}
				if tag != "" {
					jn = tag
				}
			}
			if jn == name || f.Name == name {
				return r.Field(i).Interface(), nil
			}
		}
	}
	return value.Undefined, nil
}

func appendFlattenedSequence(out []any, item any, runtime *evalRuntime) ([]any, error) {
	switch typed := item.(type) {
	case sequence:
		for _, nested := range typed {
			var err error
			out, err = appendFlattenedSequence(out, nested, runtime)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	case bound:
		return appendFlattenedSequence(out, typed.v, runtime)
	case contextual:
		return appendFlattenedSequence(out, typed.v, runtime)
	case sortedSequence:
		return appendFlattenedSequence(out, typed.values, runtime)
	case undefinedLike:
		return out, nil
	default:
		if value.IsUndefined(item) {
			return out, nil
		}
		if runtime != nil {
			if err := runtime.checkSequenceLength(len(out) + 1); err != nil {
				return nil, err
			}
		}
		return append(out, item), nil
	}
}
func toNumber(v any) float64 {
	if n, ok := numeric(v); ok {
		return n
	}
	return 0
}
func numeric(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		n, e := x.Float64()
		return n, e == nil
	case string:
		n, e := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return n, e == nil
	}
	return 0, false
}
func parseNumber(s string) (any, error) {
	sign := int64(1)
	if strings.HasPrefix(s, "-") {
		sign = -1
		s = s[1:]
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, e := strconv.ParseInt(s[2:], 16, 64)
		return float64(sign * n), e
	}
	if strings.HasPrefix(s, "0b") || strings.HasPrefix(s, "0B") {
		n, e := strconv.ParseInt(s[2:], 2, 64)
		return float64(sign * n), e
	}
	if strings.HasPrefix(s, "0o") || strings.HasPrefix(s, "0O") {
		n, e := strconv.ParseInt(s[2:], 8, 64)
		return float64(sign * n), e
	}
	n, e := strconv.ParseFloat(s, 64)
	return float64(sign) * n, e
}
func toString(v any) string {
	if value.IsUndefined(v) {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	if f, ok := numeric(v); ok {
		return formatJSONataNumber(f)
	}
	if b, ok := v.(bool); ok {
		if b {
			return "true"
		}
		return "false"
	}
	if public, ok := value.Public(collapse(v)); ok {
		b, _ := json.Marshal(public)
		return string(b)
	}
	b, _ := json.Marshal(collapse(v))
	return string(b)
}

func publicDiagnosticValue(v any) any {
	if public, ok := value.Public(collapse(v)); ok {
		return public
	}
	return v
}

func ebv(v any) bool {
	v = collapse(v)
	if value.IsUndefined(v) || v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case value.Array:
		if len(x.Items) == 0 {
			return false
		}
		for _, item := range x.Items {
			if ebv(item) {
				return true
			}
		}
		return false
	case sequence:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case value.OrderedObject:
		return len(x.Fields) > 0
	}
	if n, ok := numeric(v); ok {
		return n != 0 && !math.IsNaN(n)
	}
	return true
}

func defaultEBV(v any) bool {
	if _, ok := callable(collapse(v)); ok {
		return false
	}
	return ebv(v)
}

func emptySequence(v any) bool {
	switch x := v.(type) {
	case contextual:
		return emptySequence(x.v)
	case bound:
		return emptySequence(x.v)
	case sequence:
		return len(x) == 0
	default:
		return value.IsUndefined(v)
	}
}
func equal(a, b any) bool {
	a, b = collapse(a), collapse(b)
	if value.IsUndefined(a) || value.IsUndefined(b) {
		return false
	}
	if na, oka := strictNumeric(a); oka {
		nb, okb := strictNumeric(b)
		return okb && na == nb
	}
	return reflect.DeepEqual(comparableJSONValue(a), comparableJSONValue(b))
}

func comparableJSONValue(v any) any {
	switch x := v.(type) {
	case value.OrderedObject:
		fields := make(map[string]any, len(x.Fields))
		for key, item := range x.Fields {
			fields[key] = comparableJSONValue(item)
		}
		return fields
	case map[string]any:
		fields := make(map[string]any, len(x))
		for key, item := range x {
			fields[key] = comparableJSONValue(item)
		}
		return fields
	case value.Array:
		items := make([]any, len(x.Items))
		for index, item := range x.Items {
			items[index] = comparableJSONValue(item)
		}
		return items
	case []any:
		items := make([]any, len(x))
		for index, item := range x {
			items[index] = comparableJSONValue(item)
		}
		return items
	default:
		if number, ok := strictNumeric(v); ok {
			return number
		}
		return v
	}
}

func strictNumeric(v any) (float64, bool) {
	switch v.(type) {
	case string, bool, nil:
		return 0, false
	default:
		return numeric(v)
	}
}
func compare(a, b any) int {
	if na, ok := numeric(a); ok {
		if nb, ok := numeric(b); ok {
			if na < nb {
				return -1
			}
			if na > nb {
				return 1
			}
			return 0
		}
	}
	as, bs := toString(a), toString(b)
	if as < bs {
		return -1
	}
	if as > bs {
		return 1
	}
	return 0
}

func arithmeticNumber(v any) (float64, bool) {
	switch v.(type) {
	case string, bool, nil:
		return 0, false
	default:
		return numeric(v)
	}
}

func arithmeticTypeError(a, b any, op string) error {
	if _, ok := arithmeticNumber(a); !ok {
		return runtimeError{
			code:  "T2001",
			msg:   "The left side of the " + strconv.Quote(op) + " operator must evaluate to a number",
			value: a,
		}
	}
	if _, ok := arithmeticNumber(b); !ok {
		return runtimeError{
			code:  "T2002",
			msg:   "The right side of the " + strconv.Quote(op) + " operator must evaluate to a number",
			value: b,
		}
	}
	return runtimeError{
		code:  "T2002",
		msg:   "The right side of the " + strconv.Quote(op) + " operator must evaluate to a number",
		value: b,
	}
}

func finiteResult(v float64) (any, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, runtimeError{code: "D1001", msg: "numeric result is not finite"}
	}
	return v, nil
}

func arithmetic(a, b any, op string, fn func(float64, float64) float64) (any, error) {
	x, ok := arithmeticNumber(a)
	if !ok && !value.IsUndefined(a) {
		return nil, arithmeticTypeError(a, b, op)
	}
	y, okY := arithmeticNumber(b)
	if !okY && !value.IsUndefined(b) {
		return nil, arithmeticTypeError(a, b, op)
	}
	if value.IsUndefined(a) || value.IsUndefined(b) {
		return value.Undefined, nil
	}
	return finiteResult(fn(x, y))
}

func compareChecked(a, b any, op, invalidCode string) (any, error) {
	if value.IsUndefined(a) || value.IsUndefined(b) {
		if value.IsUndefined(a) && !value.IsUndefined(b) {
			if _, ok := strictNumeric(b); !ok {
				if _, stringOK := b.(string); !stringOK {
					return nil, runtimeError{code: invalidCode, msg: "values cannot be compared"}
				}
			}
		}
		if value.IsUndefined(b) && !value.IsUndefined(a) {
			if _, ok := strictNumeric(a); !ok {
				if _, stringOK := a.(string); !stringOK {
					return nil, runtimeError{code: invalidCode, msg: "values cannot be compared"}
				}
			}
		}
		return value.Undefined, nil
	}
	_, numA := strictNumeric(a)
	_, numB := strictNumeric(b)
	if numA != numB {
		return nil, runtimeError{code: invalidCode, msg: "values cannot be compared"}
	}
	if !numA {
		if _, okA := a.(string); !okA {
			return nil, runtimeError{code: invalidCode, msg: "values cannot be compared"}
		}
		if _, okB := b.(string); !okB {
			return nil, runtimeError{code: invalidCode, msg: "values cannot be compared"}
		}
	}
	c := compare(a, b)
	switch op {
	case "<":
		return c < 0, nil
	case "<=":
		return c <= 0, nil
	case ">":
		return c > 0, nil
	default:
		return c >= 0, nil
	}
}
func contains(container, needle any) bool {
	for _, x := range items(container) {
		if equal(x, needle) {
			return true
		}
	}
	return false
}
func numberRange(a, b any) (any, error) {
	return numberRangeWithState(state{}, a, b)
}

func numberRangeWithState(st state, a, b any) (any, error) {
	if value.IsUndefined(a) || value.IsUndefined(b) {
		if value.IsUndefined(a) {
			if _, ok := numeric(b); !ok && !value.IsUndefined(b) {
				return nil, runtimeError{code: "T2004", msg: "range endpoints must be integers"}
			}
		}
		if value.IsUndefined(b) {
			if _, ok := numeric(a); !ok && !value.IsUndefined(a) {
				return nil, runtimeError{code: "T2003", msg: "range start must be an integer"}
			}
		}
		return sequence{}, nil
	}
	x, ok := numeric(a)
	if !ok || math.Trunc(x) != x {
		return nil, runtimeError{code: "T2003", msg: "range start must be an integer"}
	}
	y, ok := numeric(b)
	if !ok || math.Trunc(y) != y {
		return nil, runtimeError{code: "T2004", msg: "range endpoints must be integers"}
	}
	if y < x {
		return sequence{}, nil
	}
	delta := y - x
	const maxRangeItems = 10000000
	// Check the floating-point span before converting it to int. A span such
	// as -1e308..1e308 is +Inf; converting that to int can wrap negative and
	// reach make with an invalid capacity before the D2014 guard runs.
	if math.IsNaN(delta) || delta >= float64(maxRangeItems) {
		attempted := delta + 1
		formatted := strconv.FormatFloat(attempted, 'f', -1, 64)
		if math.IsInf(attempted, 0) || math.IsNaN(attempted) {
			// JSONata formats diagnostic values through JSON.stringify;
			// non-finite numbers therefore render as null.
			formatted = "null"
		}
		return nil, runtimeError{
			code:  "D2014",
			msg:   "The size of the sequence allocated by the range operator (..) must not exceed 1e7.  Attempted to allocate " + formatted + ".",
			value: attempted,
		}
	}
	size := int(delta) + 1
	if st.runtime != nil {
		if err := st.runtime.checkSequenceLengthAttempted(size); err != nil {
			return nil, err
		}
	}
	capacity := bulkOperationCapacity(size, st.runtime)
	out := make([]any, 0, capacity)
	step := 1.
	for i, count := x, 0; ; i, count = i+step, count+1 {
		if st.runtime != nil && count%bulkOperationCheckStride == 0 {
			if err := st.runtime.check(); err != nil {
				return nil, err
			}
		}
		out = append(out, i)
		if i == y {
			break
		}
	}
	return sequence(out), nil
}

func validateObjectKey(key string, position syntax.Position) error {
	if key == "_jsonata_lambda" || key == "_jsonata_function" {
		return runtimeError{
			code:     "D1013",
			msg:      fmt.Sprintf("Object property names starting with _jsonata_ are reserved for internal use: %q", key),
			value:    key,
			position: position.Offset,
			hasPos:   true,
		}
	}
	return nil
}
func cloneVars(m map[string]any) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// cloneVarsMutable returns an independent map suitable for adding bindings.
// Empty variable frames are represented by nil maps until a write is needed.
func cloneVarsMutable(m map[string]any) map[string]any {
	out := cloneVars(m)
	if out == nil {
		return make(map[string]any)
	}
	return out
}

// frameFor normalizes a value entering a path step into an immutable
// evaluation frame. Parent references are frames rather than raw values so
// repeated % operations can walk the complete source lineage.
func frameFor(v any, st state) contextual {
	parent := st.parent
	var layers []map[string]any
	for {
		switch wrapped := v.(type) {
		case bound:
			layers = append(layers, wrapped.vars)
			v = wrapped.v
		case contextual:
			layers = append(layers, wrapped.vars)
			parent = wrapped.parent
			v = wrapped.v
		default:
			// Plain path values inherit the current immutable frame. Most path
			// items are unwrapped values, so copying this map here only to copy it
			// again before adding the path index is needless work. Callers that
			// need to add bindings still use cloneVarsMutable, preserving the
			// ownership boundary.
			if len(layers) == 0 {
				return contextual{v: v, parent: parent, vars: st.vars}
			}
			var vars map[string]any
			capacity := len(st.vars)
			for _, layer := range layers {
				capacity += len(layer)
			}
			if capacity != 0 {
				vars = make(map[string]any, capacity)
				for key, item := range st.vars {
					vars[key] = item
				}
			}
			for index := len(layers) - 1; index >= 0; index-- {
				for key, item := range layers[index] {
					if vars == nil {
						vars = make(map[string]any)
					}
					vars[key] = item
				}
			}
			return contextual{v: v, parent: parent, vars: vars}
		}
	}
}

// bindValues attaches a path binding to each value in a sequence. Bindings
// are part of the value's lineage, so a later path step can retain outer
// joins while evaluating the inner expression.
func bindValues(v any, name string, st state, index bool) (any, error) {
	values := items(v)
	if b, ok := v.(bound); ok {
		values = []any{b}
	}
	if len(values) == 0 {
		return value.Undefined, nil
	}
	if st.runtime != nil {
		if err := st.runtime.checkSequenceLength(len(values)); err != nil {
			return nil, err
		}
	}
	out := make([]any, 0, sequenceAllocationCapacity(len(values), st.runtime))
	for i, raw := range values {
		vars := cloneVarsMutable(st.vars)
		item := raw
		if b, ok := raw.(bound); ok {
			item = b.v
			for k, value := range b.vars {
				vars[k] = value
			}
		}
		if index {
			vars[name] = i
		} else {
			if _, ok := item.(contextual); ok {
				vars[name] = item
			} else {
				vars[name] = frameFor(item, st)
			}
		}
		out = append(out, bound{v: item, vars: vars})
	}
	if len(out) == 1 {
		return out[0], nil
	}
	return sequence(out), nil
}

type transformValue struct {
	expression syntax.Transform
	env        *lexicalEnv
	vars       map[string]any
	root       any
	parent     any
}

func newTransformValue(expression syntax.Transform, st state) *transformValue {
	return &transformValue{
		expression: expression,
		env:        stateEnv(st),
		vars:       cloneVars(st.vars),
		root:       st.root,
		parent:     st.parent,
	}
}

func (f *transformValue) callableName() string { return "transform" }

func (f *transformValue) invoke(st state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("transform", 1, len(args))
	}
	input := unwrapTransformInput(args[0])
	if value.IsUndefined(input) {
		return value.Undefined, nil
	}
	switch input.(type) {
	case map[string]any, value.OrderedObject, []any, value.Array:
	default:
		return nil, runtimeError{code: "T0410", msg: "transform input must be an object or array"}
	}
	if st.runtime != nil {
		if err := st.runtime.enterCall(); err != nil {
			return nil, err
		}
		defer st.runtime.leaveCall()
	}

	cloneBinding, ok := f.lookup("$clone")
	cloneFunction, callableClone := callable(cloneBinding)
	if !ok || !callableClone {
		return nil, transformRuntimeError("T2013", "transform clone binding must be a function", f.expression.Pos)
	}
	safeInput, err := cloneTransformValue(input, st)
	if err != nil {
		return nil, err
	}
	cloneState := state{
		root:    f.root,
		current: nil,
		parent:  f.parent,
		vars:    cloneVars(f.vars),
		env:     f.env,
		runtime: st.runtime,
	}
	result, err := cloneFunction.invoke(cloneState, []any{safeInput})
	if err != nil {
		return nil, err
	}
	result = collapse(result)
	orderChanges, err := f.apply(result, st.runtime)
	if err != nil {
		return nil, err
	}
	return normalizeTransformObjectOrder(result, st.runtime, orderChanges)
}

func (f *transformValue) lookup(name string) (any, bool) {
	if f.env != nil {
		if binding, ok := f.env.lookup(name); ok {
			return binding, true
		}
	}
	if binding, ok := f.vars[name]; ok {
		return binding, true
	}
	return builtinFor(name)
}

func (f *transformValue) apply(target any, runtime *evalRuntime) (map[uintptr]*transformOrderChanges, error) {
	orderChanges := make(map[uintptr]*transformOrderChanges)
	base := state{
		root:                target,
		current:             target,
		parent:              f.parent,
		vars:                cloneVars(f.vars),
		env:                 f.env,
		runtime:             runtime,
		preserveObjectOrder: true,
	}
	pathValue, err := eval(f.expression.Path, base)
	if err != nil || value.IsUndefined(pathValue) {
		return orderChanges, err
	}
	matches, err := transformMatches(pathValue, base)
	if err != nil {
		return nil, err
	}
	for _, match := range matches {
		if runtime != nil {
			if err := runtime.check(); err != nil {
				return nil, err
			}
		}
		frame := state{
			root:                target,
			current:             match.value,
			parent:              match.parent,
			vars:                match.vars,
			env:                 f.env,
			runtime:             runtime,
			preserveObjectOrder: true,
		}
		updated, err := eval(f.expression.Update, frame)
		if err != nil {
			return nil, err
		}
		if !value.IsUndefined(updated) {
			u, updateOrder, ok := transformObjectFields(updated)
			if !ok {
				return nil, transformRuntimeError("T2011", "transform update must evaluate to an object", transformNodePosition(f.expression.Update))
			}
			if destination, mutable := transformObject(match.value); mutable {
				orderState := transformDestinationOrderState(match.value, orderChanges)
				for _, key := range updateOrder {
					field := u[key]
					if runtime != nil {
						if err := runtime.check(); err != nil {
							return nil, err
						}
					}
					_, existed := destination[key]
					if value.IsUndefined(field) {
						delete(destination, key)
						orderState.recordDelete(key, existed)
					} else {
						field, _, _ = unwrapTransformMatch(field, nil, nil)
						cyclic, err := transformContainsObject(field, destination, runtime)
						if err != nil {
							return nil, err
						}
						if cyclic {
							return nil, runtimeError{code: "U1001", msg: "transform update would create a cyclic value"}
						}
						destination[key] = field
						orderState.recordSet(key, existed)
					}
				}
			}
		}
		if f.expression.Delete != nil {
			deleted, err := eval(f.expression.Delete, frame)
			if err != nil {
				return nil, err
			}
			keys, valid := transformDeleteKeys(deleted)
			if !valid {
				return nil, transformRuntimeError("T2012", "transform delete must evaluate to a string or array of strings", transformNodePosition(f.expression.Delete))
			}
			if destination, mutable := transformObject(match.value); mutable {
				orderState := transformDestinationOrderState(match.value, orderChanges)
				for _, key := range keys {
					if runtime != nil {
						if err := runtime.check(); err != nil {
							return nil, err
						}
					}
					_, existed := destination[key]
					delete(destination, key)
					orderState.recordDelete(key, existed)
				}
			}
		}
	}
	return orderChanges, nil
}

type transformOrderChanges struct {
	added   []string
	removed map[string]struct{}
}

func (c *transformOrderChanges) recordSet(key string, existed bool) {
	if c == nil || existed {
		return
	}
	c.added = append(c.added, key)
}

func (c *transformOrderChanges) recordDelete(key string, existed bool) {
	if c == nil || !existed {
		return
	}
	if c.removed == nil {
		c.removed = make(map[string]struct{})
	}
	c.removed[key] = struct{}{}
	for index, added := range c.added {
		if added == key {
			c.added = append(c.added[:index], c.added[index+1:]...)
			break
		}
	}
}

func transformDestinationOrderState(input any, changes map[uintptr]*transformOrderChanges) *transformOrderChanges {
	input, _, _ = unwrapTransformMatch(input, nil, nil)
	ordered, ok := input.(value.OrderedObject)
	if !ok || ordered.Fields == nil {
		return nil
	}
	pointer := reflect.ValueOf(ordered.Fields).Pointer()
	state := changes[pointer]
	if state == nil {
		state = &transformOrderChanges{}
		changes[pointer] = state
	}
	return state
}

type transformMatch struct {
	value  any
	parent any
	vars   map[string]any
}

func transformMatches(result any, base state) ([]transformMatch, error) {
	matchValue, parent, vars := unwrapTransformMatch(result, base.parent, base.vars)
	var raw []any
	switch typed := matchValue.(type) {
	case sequence:
		raw = []any(typed)
	case []any:
		raw = typed
	case value.Array:
		raw = typed.Items
	case sortedSequence:
		return transformMatches(typed.values, state{parent: parent, vars: vars, runtime: base.runtime})
	default:
		raw = []any{matchValue}
	}
	if base.runtime != nil {
		if err := base.runtime.checkSequenceLength(len(raw)); err != nil {
			return nil, err
		}
	}
	matches := make([]transformMatch, 0, sequenceAllocationCapacity(len(raw), base.runtime))
	for _, item := range raw {
		if base.runtime != nil {
			if err := base.runtime.check(); err != nil {
				return nil, err
			}
		}
		itemValue, itemParent, itemVars := unwrapTransformMatch(item, parent, vars)
		matches = append(matches, transformMatch{value: itemValue, parent: itemParent, vars: itemVars})
	}
	return matches, nil
}

func unwrapTransformMatch(input, parent any, inherited map[string]any) (any, any, map[string]any) {
	vars := cloneVarsMutable(inherited)
	for {
		switch wrapped := input.(type) {
		case contextual:
			input = wrapped.v
			parent = wrapped.parent
			for name, binding := range wrapped.vars {
				vars[name] = binding
			}
		case *contextual:
			if wrapped == nil {
				return value.Undefined, parent, vars
			}
			input = wrapped.v
			parent = wrapped.parent
			for name, binding := range wrapped.vars {
				vars[name] = binding
			}
		case bound:
			input = wrapped.v
			for name, binding := range wrapped.vars {
				vars[name] = binding
			}
		default:
			return input, parent, vars
		}
	}
}

func transformObject(input any) (map[string]any, bool) {
	matchValue, _, _ := unwrapTransformMatch(input, nil, nil)
	switch object := matchValue.(type) {
	case map[string]any:
		return object, true
	case value.OrderedObject:
		return object.Fields, true
	default:
		return nil, false
	}
}

func transformObjectFields(input any) (map[string]any, []string, bool) {
	input, _, _ = unwrapTransformMatch(input, nil, nil)
	switch object := input.(type) {
	case map[string]any:
		return object, collectionSortedKeys(object), true
	case value.OrderedObject:
		order := make([]string, 0, len(object.Fields))
		seen := make(map[string]struct{}, len(object.Fields))
		for _, key := range object.Order {
			if _, exists := object.Fields[key]; !exists {
				continue
			}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			order = append(order, key)
		}
		for _, key := range collectionSortedKeys(object.Fields) {
			if _, exists := seen[key]; exists {
				continue
			}
			order = append(order, key)
		}
		return object.Fields, value.CanonicalObjectOrder(order), true
	default:
		return nil, nil, false
	}
}

func unwrapTransformInput(input any) any {
	input = unwrapSignatureValue(input)
	if values, ok := input.(sequence); ok {
		switch len(values) {
		case 0:
			return value.Undefined
		case 1:
			return unwrapSignatureValue(values[0])
		default:
			return []any(values)
		}
	}
	return input
}

func transformContainsObject(input any, target map[string]any, runtime *evalRuntime) (bool, error) {
	targetPointer := reflect.ValueOf(target).Pointer()
	visiting := make(map[transformCloneKey]bool)
	var walk func(any) (bool, error)
	walk = func(input any) (bool, error) {
		if runtime != nil {
			if err := runtime.check(); err != nil {
				return false, err
			}
		}
		input, _, _ = unwrapTransformMatch(input, nil, nil)
		switch typed := input.(type) {
		case map[string]any:
			pointer := reflect.ValueOf(typed).Pointer()
			if pointer == targetPointer {
				return true, nil
			}
			key := transformCloneKey{kind: reflect.Map, pointer: pointer}
			if visiting[key] {
				return false, runtimeError{code: "U1001", msg: "transform update contains a cyclic value"}
			}
			visiting[key] = true
			defer delete(visiting, key)
			for _, item := range typed {
				contains, err := walk(item)
				if err != nil || contains {
					return contains, err
				}
			}
		case value.OrderedObject:
			return walk(typed.Fields)
		case sequence:
			return walk([]any(typed))
		case value.Array:
			return walk(typed.Items)
		case []any:
			key := transformCloneKey{kind: reflect.Slice, pointer: reflect.ValueOf(typed).Pointer(), length: len(typed), capacity: cap(typed)}
			if visiting[key] {
				return false, runtimeError{code: "U1001", msg: "transform update contains a cyclic value"}
			}
			visiting[key] = true
			defer delete(visiting, key)
			for _, item := range typed {
				contains, err := walk(item)
				if err != nil || contains {
					return contains, err
				}
			}
		}
		return false, nil
	}
	return walk(input)
}

func transformDeleteKeys(v any) ([]string, bool) {
	if value.IsUndefined(v) {
		return nil, true
	}
	unwrapped, _, _ := unwrapTransformMatch(v, nil, nil)
	if key, ok := unwrapped.(string); ok {
		return []string{key}, true
	}
	var items []any
	switch typed := unwrapped.(type) {
	case sequence:
		items = []any(typed)
	case []any:
		items = typed
	case value.Array:
		items = typed.Items
	default:
		return nil, false
	}
	keys := make([]string, len(items))
	for index, item := range items {
		item, _, _ = unwrapTransformMatch(item, nil, nil)
		key, ok := item.(string)
		if !ok {
			return nil, false
		}
		keys[index] = key
	}
	return keys, true
}

func normalizeTransformObjectOrder(input any, runtime *evalRuntime, changes map[uintptr]*transformOrderChanges) (any, error) {
	if runtime != nil {
		if err := runtime.enterCall(); err != nil {
			return nil, err
		}
		defer runtime.leaveCall()
	}
	switch typed := input.(type) {
	case map[string]any:
		for key, item := range typed {
			normalized, err := normalizeTransformObjectOrder(item, runtime, changes)
			if err != nil {
				return nil, err
			}
			typed[key] = normalized
		}
		return typed, nil
	case value.OrderedObject:
		for key, item := range typed.Fields {
			normalized, err := normalizeTransformObjectOrder(item, runtime, changes)
			if err != nil {
				return nil, err
			}
			typed.Fields[key] = normalized
		}
		order := make([]string, 0, len(typed.Fields))
		seen := make(map[string]struct{}, len(typed.Fields))
		change := changes[reflect.ValueOf(typed.Fields).Pointer()]
		for _, key := range typed.Order {
			if _, exists := typed.Fields[key]; !exists {
				continue
			}
			if change != nil {
				if _, removed := change.removed[key]; removed {
					continue
				}
			}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			order = append(order, key)
		}
		if change != nil {
			for _, key := range change.added {
				if _, exists := typed.Fields[key]; !exists {
					continue
				}
				if _, duplicate := seen[key]; duplicate {
					continue
				}
				seen[key] = struct{}{}
				order = append(order, key)
			}
		}
		for _, key := range collectionSortedKeys(typed.Fields) {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			order = append(order, key)
		}
		typed.Order = value.CanonicalObjectOrder(order)
		return typed, nil
	case sequence:
		for index, item := range typed {
			normalized, err := normalizeTransformObjectOrder(item, runtime, changes)
			if err != nil {
				return nil, err
			}
			typed[index] = normalized
		}
		return typed, nil
	case []any:
		for index, item := range typed {
			normalized, err := normalizeTransformObjectOrder(item, runtime, changes)
			if err != nil {
				return nil, err
			}
			typed[index] = normalized
		}
		return typed, nil
	case value.Array:
		for index, item := range typed.Items {
			normalized, err := normalizeTransformObjectOrder(item, runtime, changes)
			if err != nil {
				return nil, err
			}
			typed.Items[index] = normalized
		}
		return typed, nil
	default:
		return input, nil
	}
}

func transformRuntimeError(code, message string, position syntax.Position) error {
	return runtimeError{code: code, msg: message, position: position.Offset + 1, hasPos: true}
}

func transformNodePosition(node syntax.Node) syntax.Position {
	switch typed := node.(type) {
	case syntax.Literal:
		return typed.Pos
	case syntax.Name:
		return typed.Pos
	case syntax.Variable:
		return typed.Pos
	case syntax.Path:
		return typed.Pos
	case syntax.Binary:
		return typed.Pos
	case syntax.Bind:
		return typed.Pos
	case syntax.Unary:
		return typed.Pos
	case syntax.Array:
		return typed.Pos
	case syntax.Object:
		return typed.Pos
	case syntax.Block:
		return typed.Pos
	case syntax.Call:
		return typed.Pos
	case syntax.Lambda:
		return typed.Pos
	case syntax.Apply:
		return typed.Pos
	case syntax.Selector:
		return typed.Pos
	case syntax.Transform:
		return typed.Pos
	case syntax.Parent:
		return typed.Pos
	case syntax.Wildcard:
		return typed.Pos
	case syntax.Placeholder:
		return typed.Pos
	default:
		return syntax.Position{}
	}
}

type transformCloneKey struct {
	kind     reflect.Kind
	pointer  uintptr
	length   int
	capacity int
}

type transformCloner struct {
	st       state
	maps     map[transformCloneKey]map[string]any
	slices   map[transformCloneKey][]any
	visiting map[transformCloneKey]bool
}

func cloneTransformValue(input any, st state) (any, error) {
	cloner := transformCloner{
		st:       st,
		maps:     make(map[transformCloneKey]map[string]any),
		slices:   make(map[transformCloneKey][]any),
		visiting: make(map[transformCloneKey]bool),
	}
	return cloner.clone(input)
}

func (c *transformCloner) clone(input any) (any, error) {
	if c.st.runtime != nil {
		if err := c.st.runtime.enterCall(); err != nil {
			return nil, err
		}
		defer c.st.runtime.leaveCall()
	}
	switch typed := input.(type) {
	case contextual:
		return c.clone(typed.v)
	case *contextual:
		if typed == nil {
			return value.Undefined, nil
		}
		return c.clone(typed.v)
	case bound:
		return c.clone(typed.v)
	case map[string]any:
		return c.cloneMap(typed)
	case value.OrderedObject:
		fields, err := c.cloneMap(typed.Fields)
		if err != nil {
			return nil, err
		}
		return value.OrderedObject{Fields: fields, Order: append([]string(nil), typed.Order...)}, nil
	case sequence:
		items, err := c.cloneSlice([]any(typed))
		return sequence(items), err
	case []any:
		return c.cloneSlice(typed)
	case value.Array:
		items, err := c.cloneSlice(typed.Items)
		if err != nil {
			return nil, err
		}
		return value.Array{Items: items, Keep: typed.Keep}, nil
	default:
		return input, nil
	}
}

func (c *transformCloner) cloneMap(input map[string]any) (map[string]any, error) {
	key := transformCloneKey{kind: reflect.Map, pointer: reflect.ValueOf(input).Pointer()}
	if c.visiting[key] {
		return nil, runtimeError{code: "U1001", msg: "transform input contains a cycle"}
	}
	if cloned, ok := c.maps[key]; ok {
		return cloned, nil
	}
	cloned := make(map[string]any, len(input))
	c.maps[key] = cloned
	c.visiting[key] = true
	defer delete(c.visiting, key)
	for name, item := range input {
		value, err := c.clone(item)
		if err != nil {
			return nil, err
		}
		cloned[name] = value
	}
	return cloned, nil
}

func (c *transformCloner) cloneSlice(input []any) ([]any, error) {
	key := transformCloneKey{kind: reflect.Slice, pointer: reflect.ValueOf(input).Pointer(), length: len(input), capacity: cap(input)}
	if c.visiting[key] {
		return nil, runtimeError{code: "U1001", msg: "transform input contains a cycle"}
	}
	if cloned, ok := c.slices[key]; ok {
		return cloned, nil
	}
	cloned := make([]any, len(input))
	c.slices[key] = cloned
	c.visiting[key] = true
	defer delete(c.visiting, key)
	for index, item := range input {
		value, err := c.clone(item)
		if err != nil {
			return nil, err
		}
		cloned[index] = value
	}
	return cloned, nil
}

func deepClone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		o := make(map[string]any, len(x))
		for k, v := range x {
			o[k] = deepClone(v)
		}
		return o
	case value.OrderedObject:
		o := value.OrderedObject{Fields: make(map[string]any, len(x.Fields)), Order: append([]string(nil), x.Order...)}
		for k, v := range x.Fields {
			o.Fields[k] = deepClone(v)
		}
		return o
	case []any:
		o := make([]any, len(x))
		for i, v := range x {
			o[i] = deepClone(v)
		}
		return o
	case value.Array:
		o := value.Array{Items: make([]any, len(x.Items)), Keep: x.Keep}
		for i, v := range x.Items {
			o.Items[i] = deepClone(v)
		}
		return o
	default:
		return v
	}
}

func DecodeJSON(data []byte) (any, error) {
	return value.DecodeJSON(data)
}

// DecodeJSONWithOptions decodes JSON under the same synchronous runtime
// controls used by evaluation. Checks run before decoder reads, so a canceled
// context or exhausted budget stops parsing before the full value is built.
func DecodeJSONWithOptions(data []byte, options Options) (any, error) {
	runtime := newEvalRuntime(options)
	decoded, err := value.DecodeJSONWithOptions(data, value.DecodeOptions{
		Check:    runtime.check,
		MaxDepth: runtime.maxDepth,
	})
	if err != nil {
		return nil, normalizationRuntimeError(err)
	}
	return decoded, nil
}

// EvalBytesWithOptions decodes and evaluates with one runtime. Decoded input
// is already evaluator-owned, so it bypasses the public-input normalization
// copy while bindings and evaluation continue to share the same budget.
func EvalBytesWithOptions(n syntax.Node, data []byte, options Options) (any, error) {
	runtime := newEvalRuntime(options)
	decoded, err := value.DecodeJSONWithOptions(data, value.DecodeOptions{
		Check:    runtime.check,
		MaxDepth: runtime.maxDepth,
	})
	if err != nil {
		return nil, normalizationRuntimeError(err)
	}
	return evalWithRuntime(n, decoded, options.Bindings, runtime, true, false)
}
