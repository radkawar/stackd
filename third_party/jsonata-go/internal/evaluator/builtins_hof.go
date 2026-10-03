package evaluator

import (
	"fmt"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

var hofBuiltinSpecs = []builtinSpec{
	{name: "filter", signature: "<af>", implementation: builtinFilter},
	{name: "map", signature: "<af>", implementation: builtinMap},
	{name: "reduce", signature: "<afj?:j>", implementation: builtinReduce},
	{name: "single", signature: "<af?>", implementation: builtinSingle},
}

func builtinMap(st state, args []any) (any, error) {
	if len(args) != 2 {
		return nil, runtimeError{code: "T0410", msg: "function \"$map\" requires an array and a function"}
	}
	fn, ok := callable(args[1])
	if !ok {
		return nil, functionTypeError("map")
	}
	values := hofValues(args[0])
	if len(values) == 0 {
		return value.Undefined, nil
	}
	array := value.Array{Items: values}
	result := make([]any, 0, sequenceAllocationCapacity(len(values), st.runtime))
	for index, item := range values {
		if err := hofCheck(st); err != nil {
			return nil, err
		}
		mapped, err := invokeHOFCallback(st, fn,
			[]any{item, float64(index), array}, item, array, 1, 3)
		if err != nil {
			return nil, err
		}
		if !value.IsUndefined(mapped) {
			if st.runtime != nil {
				if err := st.runtime.checkSequenceLength(len(result) + 1); err != nil {
					return nil, err
				}
			}
			result = append(result, collapse(mapped))
		}
	}
	return hofSequence(result), nil
}

func builtinFilter(st state, args []any) (any, error) {
	if len(args) != 2 {
		return nil, runtimeError{code: "T0410", msg: "function \"$filter\" requires an array and a function"}
	}
	fn, ok := callable(args[1])
	if !ok {
		return nil, functionTypeError("filter")
	}
	values := hofValues(args[0])
	if len(values) == 0 {
		return value.Undefined, nil
	}
	array := value.Array{Items: values}
	result := make([]any, 0, sequenceAllocationCapacity(len(values), st.runtime))
	for index, item := range values {
		if err := hofCheck(st); err != nil {
			return nil, err
		}
		keep, err := invokeHOFCallback(st, fn,
			[]any{item, float64(index), array}, item, array, 1, 3)
		if err != nil {
			return nil, err
		}
		if ebv(keep) {
			if st.runtime != nil {
				if err := st.runtime.checkSequenceLength(len(result) + 1); err != nil {
					return nil, err
				}
			}
			result = append(result, item)
		}
	}
	return hofSequence(result), nil
}

func builtinReduce(st state, args []any) (any, error) {
	if len(args) < 2 || len(args) > 3 {
		return nil, functionArityError("$reduce", 2, len(args))
	}
	fn, ok := callable(args[1])
	if !ok {
		return nil, functionTypeError("reduce")
	}
	arity, err := hofCallbackArity(fn)
	if err != nil {
		return nil, err
	}
	if arity < 2 || arity > 4 {
		return nil, runtimeError{code: "D3050", msg: "function passed to $reduce must take between two and four arguments"}
	}
	values := hofValues(args[0])
	hasInitial := len(args) == 3 && !value.IsUndefined(args[2])
	if len(values) == 0 {
		if hasInitial {
			return args[2], nil
		}
		return value.Undefined, nil
	}

	var accumulator any
	start := 0
	if hasInitial {
		accumulator = args[2]
	} else {
		accumulator = values[0]
		start = 1
	}
	array := value.Array{Items: values}
	for index := start; index < len(values); index++ {
		if err := hofCheck(st); err != nil {
			return nil, err
		}
		callbackArgs := []any{accumulator, values[index], float64(index), array}
		accumulator, err = invokeHOFCallback(st, fn, callbackArgs,
			values[index], array, 2, 4)
		if err != nil {
			return nil, err
		}
	}
	return accumulator, nil
}

func builtinSingle(st state, args []any) (any, error) {
	if len(args) == 0 || len(args) > 2 {
		return nil, functionArityError("$single", 1, len(args))
	}
	values := hofValues(args[0])
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	if len(args) == 1 {
		switch len(values) {
		case 0:
			return nil, singleNoMatchError()
		case 1:
			return values[0], nil
		default:
			return nil, singleMultipleError(len(values))
		}
	}
	fn, ok := callable(args[1])
	if !ok {
		return nil, functionTypeError("single")
	}
	array := value.Array{Items: values}
	var match any
	count := 0
	for index, item := range values {
		if err := hofCheck(st); err != nil {
			return nil, err
		}
		selected, err := invokeHOFCallback(st, fn,
			[]any{item, float64(index), array}, item, array, 1, 3)
		if err != nil {
			return nil, err
		}
		if !ebv(selected) {
			continue
		}
		count++
		match = item
		if count > 1 {
			return nil, singleMultipleError(count)
		}
	}
	if count == 0 {
		return nil, singleNoMatchError()
	}
	return match, nil
}

func hofValues(input any) []any {
	raw := items(input)
	values := make([]any, 0, len(raw))
	for _, item := range raw {
		item = collapse(item)
		if !value.IsUndefined(item) {
			values = append(values, item)
		}
	}
	return values
}

func hofSequence(values []any) any {
	if len(values) == 0 {
		return value.Undefined
	}
	return sequence(values)
}

func hofCheck(st state) error {
	if st.runtime == nil {
		return nil
	}
	return st.runtime.check()
}

func invokeHOFCallback(st state, fn callableValue, args []any, current, parent any, minArity, maxArity int) (any, error) {
	arity, err := hofCallbackArity(fn)
	if err != nil {
		return nil, err
	}
	if arity < minArity || arity > maxArity {
		return nil, runtimeError{code: "T0410", msg: fmt.Sprintf("function %q must take between %d and %d arguments", fn.callableName(), minArity, maxArity)}
	}
	if arity > len(args) {
		return nil, functionArityError(fn.callableName(), arity, len(args))
	}
	callState := st
	callState.current = current
	callState.parent = parent
	callState.tail = false
	return fn.invoke(callState, args[:arity])
}

func hofCallbackArity(fn callableValue) (int, error) {
	switch current := fn.(type) {
	case *lambdaValue:
		return len(current.params), nil
	case builtinValue:
		if current.spec.signature == "" {
			return 1, nil
		}
		signature, err := parseFunctionSignature(current.spec.signature)
		if err != nil {
			return 0, runtimeError{code: "T0410", msg: err.Error()}
		}
		arity := len(signature.params)
		for arity > 1 && signature.params[arity-1].optional {
			arity--
		}
		return arity, nil
	case *partialValue:
		arity, err := hofCallbackArity(current.fn)
		if err != nil {
			return 0, err
		}
		for _, argument := range current.args {
			if !argument.placeholder {
				arity--
			}
		}
		if arity < 0 {
			arity = 0
		}
		return arity, nil
	case interface{ callbackArity() int }:
		return current.callbackArity(), nil
	default:
		return 1, nil
	}
}

func singleNoMatchError() error {
	return runtimeError{code: "D3139", msg: "no matching value found for function $single"}
}

func singleMultipleError(count int) error {
	return runtimeError{code: "D3138", msg: fmt.Sprintf("multiple matching values found for function $single: %d", count)}
}
