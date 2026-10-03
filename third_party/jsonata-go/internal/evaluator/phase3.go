package evaluator

import (
	"fmt"

	"github.com/tiaanduplessis/jsonata-go/internal/syntax"
	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

// lexicalEnv is a linked set of lexical frames. Frames are immutable after
// construction; recursive bindings use cells owned by their defining frame.
type lexicalEnv struct {
	parent *lexicalEnv
	values map[string]any
}

type lexicalCell struct {
	value       any
	initialized bool
}

func newLexicalEnv(parent *lexicalEnv) *lexicalEnv {
	return &lexicalEnv{parent: parent}
}

func (e *lexicalEnv) bindFrame(values map[string]any) *lexicalEnv {
	if len(values) == 0 {
		return e
	}
	child := newLexicalEnv(e)
	child.values = make(map[string]any, len(values))
	for name, value := range values {
		child.values[name] = value
	}
	return child
}

func (e *lexicalEnv) lookup(name string) (any, bool) {
	for current := e; current != nil; current = current.parent {
		v, ok := current.values[name]
		if !ok {
			continue
		}
		if cell, ok := v.(*lexicalCell); ok {
			if !cell.initialized {
				return value.Undefined, true
			}
			return cell.value, true
		}
		return v, true
	}
	return nil, false
}

func (e *lexicalEnv) currentCell(name string) (*lexicalCell, bool) {
	v, ok := e.values[name]
	if !ok {
		return nil, false
	}
	cell, ok := v.(*lexicalCell)
	return cell, ok
}

type callableValue interface {
	invoke(state, []any) (any, error)
	callableName() string
}

type lambdaValue struct {
	name      string
	params    []string
	body      syntax.Node
	env       *lexicalEnv
	signature string
	root      any
	current   any
	parent    any
}

type signatureParam struct {
	kind           byte
	choices        string
	item           *signatureParam
	function       *functionSignature
	optional       bool
	variadic       bool
	contextDefault bool
}

type functionSignature struct {
	// returnType is parsed for complete signature grammar and nested function
	// descriptors. Lambda return values retain normal JSONata sequence
	// semantics, so they are not coerced at the call boundary.
	params     []signatureParam
	returnType *signatureParam
}

func (f *lambdaValue) callableName() string { return f.name }

func (f *lambdaValue) invoke(st state, args []any) (any, error) {
	if st.runtime != nil {
		if err := st.runtime.enterStackCall(); err != nil {
			return nil, err
		}
		defer st.runtime.leaveCall()
	}
	current := f
	currentArgs := args
	for {
		if current.signature != "" {
			parsed, err := parseFunctionSignature(current.signature)
			if err != nil {
				return nil, runtimeError{code: "T0410", msg: err.Error()}
			}
			currentArgs, err = prepareSignatureArgs(parsed, currentArgs, signatureContext(parsed, st.current), st.runtime)
			if err != nil {
				return nil, err
			}
		} else if len(currentArgs) > len(current.params) {
			return nil, functionArityError(current.name, len(current.params), len(currentArgs))
		}
		if len(currentArgs) < len(current.params) {
			padded := make([]any, len(current.params))
			copy(padded, currentArgs)
			for i := len(currentArgs); i < len(padded); i++ {
				padded[i] = value.Undefined
			}
			currentArgs = padded
		}
		values := make(map[string]any, len(current.params))
		for i, name := range current.params {
			values[name] = currentArgs[i]
		}
		callState := st
		callState.root = current.root
		callState.current = current.current
		callState.parent = current.parent
		callState.env = current.env.bindFrame(values)
		callState.tail = true
		result, err := evalWithBindings(current.body, callState)
		if err != nil {
			return nil, err
		}
		next, ok := result.(tailCall)
		if !ok {
			return result, nil
		}
		nextLambda, ok := next.fn.(*lambdaValue)
		if !ok {
			return next.fn.invoke(st, next.args)
		}
		if st.runtime != nil {
			if err := st.runtime.check(); err != nil {
				return nil, err
			}
		}
		current = nextLambda
		currentArgs = next.args
	}
}

func parseFunctionSignature(raw string) (functionSignature, error) {
	if len(raw) < 3 || raw[0] != '<' || raw[len(raw)-1] != '>' {
		return functionSignature{}, fmt.Errorf("invalid function signature")
	}
	body := raw[1 : len(raw)-1]
	paramsText, returnText := splitSignatureReturn(body)
	params, err := parseSignatureParams(paramsText)
	if err != nil {
		return functionSignature{}, err
	}
	result := functionSignature{params: params}
	if returnText != "" {
		index := 0
		returnType, err := parseSignatureType(returnText, &index)
		if err != nil || index != len(returnText) {
			return functionSignature{}, fmt.Errorf("invalid function signature")
		}
		result.returnType = &returnType
	}
	return result, nil
}

func signatureContext(signature functionSignature, current any) any {
	for _, param := range signature.params {
		if param.contextDefault {
			return collapse(current)
		}
	}
	return value.Undefined
}

func parseSignatureParams(raw string) ([]signatureParam, error) {
	params := make([]signatureParam, 0)
	for i := 0; i < len(raw); {
		if raw[i] == '-' {
			if len(params) == 0 {
				return nil, fmt.Errorf("invalid function signature")
			}
			params[len(params)-1].contextDefault = true
			i++
			continue
		}
		param, next, err := parseSignatureTypeAt(raw, i)
		if err != nil {
			return nil, err
		}
		params = append(params, param)
		i = next
	}
	return params, nil
}

func splitSignatureReturn(raw string) (string, string) {
	depth := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '<', '(':
			depth++
		case '>', ')':
			depth--
		case ':':
			if depth == 0 {
				return raw[:i], raw[i+1:]
			}
		}
	}
	return raw, ""
}

func parseSignatureType(raw string, index *int) (signatureParam, error) {
	param, next, err := parseSignatureTypeAt(raw, *index)
	if err != nil {
		return signatureParam{}, err
	}
	*index = next
	return param, nil
}

func parseSignatureTypeAt(raw string, start int) (signatureParam, int, error) {
	if start >= len(raw) {
		return signatureParam{}, start, fmt.Errorf("invalid function signature")
	}
	param := signatureParam{}
	index := start
	if raw[index] == '(' {
		end := findSignatureClose(raw, index, '(', ')')
		if end < 0 {
			return signatureParam{}, index, fmt.Errorf("invalid function signature")
		}
		param.choices = raw[index+1 : end]
		index = end + 1
	} else {
		param.kind = raw[index]
		index++
		if index < len(raw) && raw[index] == '<' {
			end := findSignatureClose(raw, index, '<', '>')
			if end < 0 {
				return signatureParam{}, index, fmt.Errorf("invalid function signature")
			}
			nested := raw[index : end+1]
			if param.kind == 'a' {
				children, err := parseSignatureParams(nested[1 : len(nested)-1])
				if err != nil || len(children) != 1 {
					return signatureParam{}, index, fmt.Errorf("invalid function signature")
				}
				param.item = &children[0]
			} else if param.kind == 'f' {
				signature, err := parseFunctionSignature(nested)
				if err != nil {
					return signatureParam{}, index, err
				}
				param.function = &signature
			} else {
				return signatureParam{}, index, fmt.Errorf("invalid function signature")
			}
			index = end + 1
		}
	}
	if index < len(raw) && (raw[index] == '?' || raw[index] == '+') {
		param.optional = raw[index] == '?'
		param.variadic = raw[index] == '+'
		index++
	}
	return param, index, nil
}

func findSignatureClose(raw string, start int, open, close byte) int {
	depth := 0
	for i := start; i < len(raw); i++ {
		if raw[i] == open {
			depth++
		} else if raw[i] == close {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func signatureMatches(param signatureParam, arg any) bool {
	matched, _ := signatureMatchesWithRuntime(param, arg, nil)
	return matched
}

func signatureMatchesWithRuntime(param signatureParam, arg any, runtime *evalRuntime) (bool, error) {
	if runtime != nil {
		if err := runtime.check(); err != nil {
			return false, err
		}
	}
	arg = unwrapSignatureValue(arg)
	if value.IsUndefined(arg) {
		return true, nil
	}
	if param.choices != "" {
		for _, choice := range param.choices {
			if choice == 'a' {
				switch arg.(type) {
				case value.Array, []any, sequence:
					return true, nil
				}
				continue
			}
			matched, err := signatureMatchesWithRuntime(signatureParam{kind: byte(choice)}, arg, runtime)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	}
	switch param.kind {
	case 'a':
		array, ok := signatureArrayItems(arg)
		if !ok {
			return false, nil
		}
		if param.item == nil {
			return true, nil
		}
		for _, item := range array.Items {
			matched, err := signatureMatchesWithRuntime(*param.item, item, runtime)
			if err != nil {
				return false, err
			}
			if !matched {
				return false, nil
			}
		}
		return true, nil
	case 'b':
		_, ok := arg.(bool)
		return ok, nil
	case 'f':
		fn, ok := callable(arg)
		if !ok {
			return false, nil
		}
		if param.function == nil {
			return true, nil
		}
		actual, ok := callableSignature(fn)
		return ok && signaturesMatch(*param.function, actual), nil
	case 'l':
		return arg == nil, nil
	case 'n':
		_, ok := strictNumeric(arg)
		return ok, nil
	case 'o':
		switch arg.(type) {
		case map[string]any, value.OrderedObject:
			return true, nil
		default:
			return false, nil
		}
	case 's':
		switch arg.(type) {
		case string, syntax.UTF16String:
			return true, nil
		default:
			return false, nil
		}
	case 'u':
		return value.IsUndefined(arg), nil
	case 'j':
		return isJSONSignatureValue(arg), nil
	case 'x':
		return true, nil
	default:
		return false, nil
	}
}

func isJSONSignatureValue(v any) bool {
	v = unwrapSignatureValue(v)
	if value.IsUndefined(v) {
		return false
	}
	if _, ok := callable(v); ok {
		return false
	}
	switch current := v.(type) {
	case nil, bool, string:
		return true
	case value.Array:
		for _, item := range current.Items {
			if !isJSONSignatureValue(item) {
				return false
			}
		}
		return true
	case []any:
		for _, item := range current {
			if !isJSONSignatureValue(item) {
				return false
			}
		}
		return true
	case sequence:
		for _, item := range current {
			if !isJSONSignatureValue(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, item := range current {
			if !isJSONSignatureValue(item) {
				return false
			}
		}
		return true
	case value.OrderedObject:
		for _, item := range current.Fields {
			if !isJSONSignatureValue(item) {
				return false
			}
		}
		return true
	default:
		_, ok := strictNumeric(current)
		return ok
	}
}

func signatureArrayItems(arg any) (value.Array, bool) {
	arg = unwrapSignatureValue(arg)
	if array, ok := arg.(value.Array); ok {
		return array, true
	}
	if sequence, ok := arg.(sequence); ok {
		return value.Array{Items: append([]any(nil), sequence...)}, true
	}
	if items, ok := arg.([]any); ok {
		return value.Array{Items: items}, true
	}
	if value.IsUndefined(arg) {
		return value.Array{}, true
	}
	return value.Array{Items: []any{arg}}, true
}

func unwrapSignatureValue(arg any) any {
	switch current := arg.(type) {
	case contextual:
		return unwrapSignatureValue(current.v)
	case bound:
		return unwrapSignatureValue(current.v)
	case sortedSequence:
		return unwrapSignatureValue(current.values)
	default:
		return arg
	}
}

func normalizeSignatureArg(param signatureParam, arg any, runtime *evalRuntime) (any, bool, error) {
	matched, err := signatureMatchesWithRuntime(param, arg, runtime)
	if err != nil {
		return nil, false, err
	}
	if !matched {
		return nil, false, nil
	}
	if param.kind != 'a' || value.IsUndefined(arg) {
		return arg, true, nil
	}
	array, ok := signatureArrayItems(arg)
	if !ok {
		return nil, false, nil
	}
	return array, true, nil
}

func prepareSignatureArgs(signature functionSignature, args []any, context any, runtime *evalRuntime) ([]any, error) {
	return prepareSignatureArgsMode(signature, args, context, runtime, false)
}

func prepareBuiltinSignatureArgs(signature functionSignature, args []any, context any, runtime *evalRuntime) ([]any, error) {
	return prepareSignatureArgsMode(signature, args, context, runtime, true)
}

func prepareSignatureArgsMode(signature functionSignature, args []any, context any, runtime *evalRuntime, builtin bool) ([]any, error) {
	prepared, ok, code, err := matchSignatureParams(signature.params, args, context, runtime, builtin)
	if err != nil {
		return nil, err
	}
	if !ok {
		if code == "" {
			code = "T0410"
		}
		return nil, runtimeError{code: code, msg: "function argument does not match its signature"}
	}
	return prepared, nil
}

func matchSignatureParams(params []signatureParam, args []any, context any, runtime *evalRuntime, builtin bool) ([]any, bool, string, error) {
	var match func(int, int) ([]any, bool, string, error)
	match = func(paramIndex, argIndex int) ([]any, bool, string, error) {
		if runtime != nil {
			if err := runtime.check(); err != nil {
				return nil, false, "", err
			}
		}
		if paramIndex == len(params) {
			if argIndex == len(args) {
				return nil, true, "", nil
			}
			return nil, false, "T0410", nil
		}
		param := params[paramIndex]
		if param.contextDefault {
			explicitCode := "T0410"
			if argIndex < len(args) {
				argValue, ok, err := normalizeSignatureArg(param, args[argIndex], runtime)
				if err != nil {
					return nil, false, "", err
				}
				if ok {
					rest, matched, code, err := match(paramIndex+1, argIndex+1)
					if err != nil {
						return nil, false, "", err
					}
					if matched {
						return append([]any{argValue}, rest...), true, "", nil
					}
					explicitCode = code
				} else {
					explicitCode = signatureMismatchCode(param)
				}
			}
			rest, tailOK, tailCode, err := match(paramIndex+1, argIndex)
			if err != nil {
				return nil, false, "", err
			}
			if !tailOK {
				if argIndex < len(args) {
					return nil, false, explicitCode, nil
				}
				return nil, false, tailCode, nil
			}
			contextValue, contextOK, err := normalizeSignatureArg(param, context, runtime)
			if err != nil {
				return nil, false, "", err
			}
			if !contextOK {
				return nil, false, "T0411", nil
			}
			return append([]any{contextValue}, rest...), true, "", nil
		}
		if param.variadic {
			code := "T0410"
			for count := len(args) - argIndex; count >= 1; count-- {
				values := make([]any, count)
				valid := true
				for i := 0; i < count; i++ {
					value, ok, err := normalizeSignatureArg(param, args[argIndex+i], runtime)
					if err != nil {
						return nil, false, "", err
					}
					if !ok {
						code = signatureMismatchCode(param)
						valid = false
						break
					}
					values[i] = value
				}
				if !valid {
					continue
				}
				rest, ok, restCode, err := match(paramIndex+1, argIndex+count)
				if err != nil {
					return nil, false, "", err
				}
				if ok {
					return append(values, rest...), true, "", nil
				}
				code = restCode
			}
			return nil, false, code, nil
		}
		if argIndex < len(args) {
			argValue, ok, err := normalizeSignatureArg(param, args[argIndex], runtime)
			if err != nil {
				return nil, false, "", err
			}
			if ok {
				rest, matched, code, err := match(paramIndex+1, argIndex+1)
				if err != nil {
					return nil, false, "", err
				}
				if matched {
					return append([]any{argValue}, rest...), true, "", nil
				}
				if param.optional {
					if skipped, skippedOK, skippedCode, err := match(paramIndex+1, argIndex); err != nil {
						return nil, false, "", err
					} else if skippedOK {
						return append([]any{value.Undefined}, skipped...), true, "", nil
					} else {
						return nil, false, skippedCode, nil
					}
				}
				return nil, false, code, nil
			}
			if !param.optional {
				return nil, false, signatureMismatchCode(param), nil
			}
		}
		if param.optional {
			rest, matched, code, err := match(paramIndex+1, argIndex)
			if err != nil || !matched {
				return nil, false, code, err
			}
			if paramIndex+1 < len(params) && !params[paramIndex+1].variadic {
				return append([]any{value.Undefined}, rest...), true, "", nil
			}
			return rest, true, "", nil
		}
		// A builtin's required parameter is a call-site arity error. A missing
		// context-default parameter is handled above as T0411.
		if builtin && !param.contextDefault {
			return nil, false, "T0410", nil
		}
		return nil, false, "T0411", nil
	}
	return match(0, 0)
}

func signatureMismatchCode(param signatureParam) string {
	if param.kind == 'a' {
		return "T0412"
	}
	return "T0410"
}

func callableSignature(fn callableValue) (functionSignature, bool) {
	switch value := fn.(type) {
	case builtinValue:
		if value.spec.signature == "" {
			return functionSignature{}, false
		}
		signature, err := builtinSignature(value.spec)
		return signature, err == nil
	case *lambdaValue:
		if value.signature == "" {
			return functionSignature{}, false
		}
		signature, err := parseFunctionSignature(value.signature)
		return signature, err == nil
	case *partialValue:
		return callableSignature(value.fn)
	default:
		return functionSignature{}, false
	}
}

func signaturesMatch(expected, actual functionSignature) bool {
	if len(expected.params) != len(actual.params) {
		return false
	}
	for i := range expected.params {
		if !signatureParamsMatch(expected.params[i], actual.params[i]) {
			return false
		}
	}
	if expected.returnType == nil || actual.returnType == nil {
		return expected.returnType == actual.returnType
	}
	return signatureParamsMatch(*expected.returnType, *actual.returnType)
}

func signatureParamsMatch(expected, actual signatureParam) bool {
	if expected.kind != actual.kind || expected.choices != actual.choices ||
		expected.optional != actual.optional || expected.variadic != actual.variadic ||
		expected.contextDefault != actual.contextDefault {
		return false
	}
	if expected.item == nil || actual.item == nil {
		if expected.item != nil || actual.item != nil {
			return false
		}
	} else if !signatureParamsMatch(*expected.item, *actual.item) {
		return false
	}
	if expected.function == nil || actual.function == nil {
		return expected.function == nil && actual.function == nil
	}
	return signaturesMatch(*expected.function, *actual.function)
}

type partialArg struct {
	value       any
	placeholder bool
}

type partialValue struct {
	fn   callableValue
	args []partialArg
}

func (f *partialValue) callableName() string { return f.fn.callableName() }
func (f *partialValue) invoke(st state, args []any) (any, error) {
	merged := make([]partialArg, 0, len(f.args)+len(args))
	remaining := append([]any(nil), args...)
	for _, arg := range f.args {
		if arg.placeholder {
			if len(remaining) == 0 {
				merged = append(merged, partialArg{placeholder: true})
				continue
			}
			merged = append(merged, partialArg{value: remaining[0]})
			remaining = remaining[1:]
			continue
		}
		merged = append(merged, partialArg{value: arg.value})
	}
	for _, arg := range remaining {
		merged = append(merged, partialArg{value: arg})
	}
	for _, arg := range merged {
		if arg.placeholder {
			return &partialValue{fn: f.fn, args: merged}, nil
		}
	}
	values := make([]any, len(merged))
	for i, arg := range merged {
		values[i] = arg.value
	}
	if err := rejectUTF16StringArguments(f.fn.callableName(), values); err != nil {
		return nil, err
	}
	return f.fn.invoke(st, values)
}

type composedValue struct {
	left  callableValue
	right callableValue
}

func (f *composedValue) callableName() string { return "composition" }
func (f *composedValue) invoke(st state, args []any) (any, error) {
	first, err := f.left.invoke(st, args)
	if err != nil {
		return nil, err
	}
	return f.right.invoke(st, []any{first})
}

func callable(v any) (callableValue, bool) {
	fn, ok := v.(callableValue)
	return fn, ok
}

func functionArityError(name string, expected, received int) error {
	code := "T0410"
	if received < expected {
		code = "T0411"
	}
	return runtimeError{code: code, msg: fmt.Sprintf("function %q expected %d argument(s), got %d", name, expected, received)}
}

func functionTypeError(name string) error {
	return runtimeError{code: "T0412", msg: fmt.Sprintf("argument to function %q must be a function", name)}
}

func stateEnv(st state) *lexicalEnv {
	if st.env == nil {
		st.env = newLexicalEnv(nil)
	}
	missing := make(map[string]any)
	for name, v := range st.vars {
		if _, exists := st.env.lookup(name); !exists {
			missing[name] = v
		}
	}
	if len(missing) != 0 {
		st.env = st.env.bindFrame(missing)
	}
	return st.env
}

func makeLambda(x syntax.Lambda, st state) *lambdaValue {
	params := make([]string, len(x.Params))
	for i, param := range x.Params {
		params[i] = param.Name
	}
	return &lambdaValue{
		params:    params,
		body:      x.Body,
		env:       stateEnv(st),
		signature: x.Signature,
		root:      st.root,
		current:   st.current,
		parent:    st.parent,
	}
}

func evalWithBindings(n syntax.Node, st state) (any, error) {
	if bind, ok := n.(syntax.Bind); ok {
		v, _, err := evaluateBinding(bind, st)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
	if block, ok := n.(syntax.Block); ok {
		return evalBlock(block, st)
	}
	return eval(n, st)
}

func evaluateBinding(bind syntax.Bind, st state) (any, state, error) {
	local := st
	local.tail = false
	local.env = stateEnv(st)
	cell, exists := local.env.currentCell(bind.Variable.Name)
	if !exists {
		cell = &lexicalCell{}
		local.env = local.env.bindFrame(map[string]any{bind.Variable.Name: cell})
	}
	v, next, err := evalNodeWithState(bind.Value, local)
	if err != nil {
		return nil, st, err
	}
	cell.value = v
	cell.initialized = true
	return v, next, nil
}

func evalNodeWithState(n syntax.Node, st state) (any, state, error) {
	if bind, ok := n.(syntax.Bind); ok {
		return evaluateBinding(bind, st)
	}
	v, err := evalWithBindings(n, st)
	return v, st, err
}

func evalBlock(block syntax.Block, st state) (any, error) {
	local := st
	local.env = stateEnv(st)
	cells := make(map[string]*lexicalCell)
	for _, expression := range block.Expressions {
		bind, ok := expression.(syntax.Bind)
		if !ok {
			continue
		}
		if _, exists := cells[bind.Variable.Name]; exists {
			continue
		}
		cell := &lexicalCell{}
		if existing, initialized := local.env.lookup(bind.Variable.Name); initialized {
			cell.value = existing
			cell.initialized = true
		}
		cells[bind.Variable.Name] = cell
	}
	local.env = local.env.bindFrame(cellsAsValues(cells))
	result := any(value.Undefined)
	for index, expression := range block.Expressions {
		if bind, ok := expression.(syntax.Bind); ok {
			v, next, err := evaluateBinding(bind, local)
			if err != nil {
				return nil, err
			}
			local = next
			result = v
			continue
		}
		var err error
		expressionState := local
		expressionState.tail = st.tail && index == len(block.Expressions)-1
		result, err = evalWithBindings(expression, expressionState)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func cellsAsValues(cells map[string]*lexicalCell) map[string]any {
	values := make(map[string]any, len(cells))
	for name, cell := range cells {
		values[name] = cell
	}
	return values
}

func evaluateCall(st state, fn any, args []any, partial bool) (any, error) {
	call, ok := callable(fn)
	if !ok {
		code := "T1008"
		return nil, runtimeError{code: code, msg: "attempted to call a non-function"}
	}
	if partial {
		parts := make([]partialArg, len(args))
		for i, arg := range args {
			if _, ok := arg.(placeholderValue); ok {
				parts[i].placeholder = true
			} else {
				parts[i].value = arg
			}
		}
		return &partialValue{fn: call, args: parts}, nil
	}
	if err := rejectUTF16StringArguments(call.callableName(), args); err != nil {
		return nil, err
	}
	if st.tail {
		if _, ok := call.(*lambdaValue); ok {
			return tailCall{fn: call, args: args}, nil
		}
	}
	return call.invoke(st, args)
}

func applyNode(node syntax.Apply, st state) (any, error) {
	leftState := st
	leftState.tail = false
	left, err := evalWithBindings(node.Left, leftState)
	if err != nil {
		return nil, err
	}
	if call, ok := node.Right.(syntax.Call); ok {
		if leftFn, leftCallable := callable(left); leftCallable && call.Partial {
			right, err := evalWithBindings(call, st)
			if err != nil {
				return nil, err
			}
			rightFn, rightCallable := callable(right)
			if !rightCallable {
				return nil, runtimeError{code: "T2006", msg: "right operand of ~> must be a function"}
			}
			return &composedValue{left: leftFn, right: rightFn}, nil
		}
		return applyCallWithInput(call, left, st)
	}
	if selector, ok := node.Right.(syntax.Selector); ok {
		if call, ok := selector.Base.(syntax.Call); ok {
			result, err := applyCallWithInput(call, left, st)
			if err != nil {
				return nil, err
			}
			return selectValue(result, selector.Index, st)
		}
	}
	right, err := evalWithBindings(node.Right, st)
	if err != nil {
		return nil, err
	}
	leftFn, leftCallable := callable(left)
	rightFn, rightCallable := callable(right)
	if leftCallable && rightCallable {
		return &composedValue{left: leftFn, right: rightFn}, nil
	}
	if !rightCallable {
		return nil, runtimeError{code: "T2006", msg: "right operand of ~> must be a function"}
	}
	if err := rejectUTF16StringArguments(rightFn.callableName(), []any{left}); err != nil {
		return nil, err
	}
	if st.tail {
		if _, ok := rightFn.(*lambdaValue); ok {
			return tailCall{fn: rightFn, args: []any{left}}, nil
		}
	}
	return rightFn.invoke(st, []any{left})
}

func applyCallWithInput(call syntax.Call, left any, st state) (any, error) {
	callState := st
	callState.tail = false
	fn, err := evalWithBindings(call.Function, callState)
	if err != nil {
		return nil, err
	}
	callState = stringArgumentState(callState, fn)
	args, partial, err := evaluateCallArgs(call.Args, callState)
	if err != nil {
		return nil, err
	}
	args = applyArgument(args, collapse(left))
	return evaluateCall(st, fn, args, partial || call.Partial)
}

func applyArgument(args []any, value any) []any {
	for i, arg := range args {
		if _, ok := arg.(placeholderValue); ok {
			out := append([]any(nil), args...)
			out[i] = value
			return out
		}
	}
	return append([]any{value}, args...)
}

type placeholderValue struct{}

func evaluateCallArgs(args []syntax.Node, st state) ([]any, bool, error) {
	values := make([]any, len(args))
	partial := false
	for i, arg := range args {
		if _, ok := arg.(syntax.Placeholder); ok {
			values[i] = placeholderValue{}
			partial = true
			continue
		}
		v, err := evalWithBindings(arg, st)
		if err != nil {
			return nil, false, err
		}
		values[i] = v
	}
	return values, partial, nil
}
