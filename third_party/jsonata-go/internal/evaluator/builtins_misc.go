package evaluator

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"reflect"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

var miscBuiltinSpecs = []builtinSpec{
	{name: "clone", signature: "<(oa)-:o>", implementation: builtinClone},
	{name: "random", signature: "<:n>", implementation: builtinRandom},
}

func builtinRandom(st state, args []any) (any, error) {
	if len(args) != 0 {
		return nil, functionArityError("$random", 0, len(args))
	}
	if st.runtime != nil {
		if err := st.runtime.check(); err != nil {
			return nil, err
		}
	}
	return rand.Float64(), nil
}

func builtinClone(st state, args []any) (any, error) {
	if len(args) != 1 {
		return nil, functionArityError("$clone", 1, len(args))
	}
	arg := unwrapSignatureValue(args[0])
	if value.IsUndefined(arg) {
		return value.Undefined, nil
	}
	switch arg.(type) {
	case value.Array, []any, sequence, map[string]any, value.OrderedObject:
	default:
		return nil, cloneSignatureError()
	}
	return cloneJSONataValue(st, arg, make(map[cloneVisit]struct{}))
}

type cloneVisit struct {
	kind  reflect.Kind
	type_ reflect.Type
	ptr   uintptr
}

func cloneJSONataValue(st state, input any, visiting map[cloneVisit]struct{}) (result any, err error) {
	if st.runtime != nil {
		if err := st.runtime.enterCall(); err != nil {
			return nil, err
		}
		defer st.runtime.leaveCall()
	}

	if value.IsUndefined(input) {
		return value.Undefined, nil
	}
	if _, ok := callable(input); ok {
		// JSONata stringifies nested function values as an empty string before
		// parsing the clone. Never retain an executable value in the result.
		return "", nil
	}

	switch current := input.(type) {
	case contextual:
		return cloneJSONataValue(st, current.v, visiting)
	case bound:
		return cloneJSONataValue(st, current.v, visiting)
	case sortedSequence:
		return cloneJSONataValue(st, current.values, visiting)
	case sequence:
		finish, err := beginCloneVisit(current, visiting)
		if err != nil {
			return nil, err
		}
		defer finish()
		items, err := cloneJSONataItems(st, []any(current), visiting)
		if err != nil {
			return nil, err
		}
		return value.Array{Items: items}, nil
	case value.Array:
		finish, err := beginCloneVisit(current.Items, visiting)
		if err != nil {
			return nil, err
		}
		defer finish()
		items, err := cloneJSONataItems(st, current.Items, visiting)
		if err != nil {
			return nil, err
		}
		return value.Array{Items: items, Keep: current.Keep}, nil
	case []any:
		finish, err := beginCloneVisit(current, visiting)
		if err != nil {
			return nil, err
		}
		defer finish()
		items, err := cloneJSONataItems(st, current, visiting)
		if err != nil {
			return nil, err
		}
		return value.Array{Items: items}, nil
	case map[string]any:
		finish, err := beginCloneVisit(current, visiting)
		if err != nil {
			return nil, err
		}
		defer finish()
		out := make(map[string]any)
		for key, item := range current {
			cloned, err := cloneJSONataValue(st, item, visiting)
			if err != nil {
				return nil, err
			}
			out[key] = cloned
		}
		return out, nil
	case value.OrderedObject:
		finish, err := beginCloneVisit(current.Fields, visiting)
		if err != nil {
			return nil, err
		}
		defer finish()
		fields := make(map[string]any)
		for key, item := range current.Fields {
			cloned, err := cloneJSONataValue(st, item, visiting)
			if err != nil {
				return nil, err
			}
			fields[key] = cloned
		}
		return value.OrderedObject{
			Fields: fields,
			Order:  append([]string(nil), current.Order...),
		}, nil
	case json.Number:
		number, parseErr := current.Float64()
		if parseErr != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, cloneNumberError()
		}
		return current, nil
	case nil, bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return current, nil
	case float32:
		if math.IsNaN(float64(current)) || math.IsInf(float64(current), 0) {
			return nil, cloneNumberError()
		}
		return current, nil
	case float64:
		if math.IsNaN(current) || math.IsInf(current, 0) {
			return nil, cloneNumberError()
		}
		return current, nil
	default:
		return nil, cloneTypeError()
	}
}

func cloneJSONataItems(st state, input []any, visiting map[cloneVisit]struct{}) ([]any, error) {
	result := make([]any, 0)
	for _, item := range input {
		cloned, err := cloneJSONataValue(st, item, visiting)
		if err != nil {
			return nil, err
		}
		result = append(result, cloned)
	}
	return result, nil
}

func beginCloneVisit(input any, visiting map[cloneVisit]struct{}) (func(), error) {
	reflected := reflect.ValueOf(input)
	if !reflected.IsValid() || reflected.IsNil() {
		return func() {}, nil
	}
	visit := cloneVisit{kind: reflected.Kind(), type_: reflected.Type(), ptr: reflected.Pointer()}
	if _, exists := visiting[visit]; exists {
		return nil, cloneTypeError()
	}
	visiting[visit] = struct{}{}
	return func() { delete(visiting, visit) }, nil
}

func cloneTypeError() error {
	return runtimeError{code: "T0412", msg: "argument to function $clone is not JSON-compatible"}
}

func cloneSignatureError() error {
	return runtimeError{code: "T0410", msg: "function argument does not match its signature"}
}

func cloneNumberError() error {
	return runtimeError{code: "D1001", msg: "numeric value is not finite"}
}
