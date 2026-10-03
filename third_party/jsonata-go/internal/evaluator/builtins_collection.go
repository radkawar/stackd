package evaluator

import (
	"math"
	"math/rand"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tiaanduplessis/jsonata-go/internal/value"
)

var collectionBuiltinSpecs = []builtinSpec{
	{name: "average", signature: "<a<n>:n>", implementation: builtinAverage},
	{name: "count", signature: "<a:n>", implementation: builtinCount},
	{name: "length", signature: "<s-:n>", implementation: builtinLength},
	{name: "max", signature: "<a<n>:n>", implementation: builtinMax},
	{name: "min", signature: "<a<n>:n>", implementation: builtinMin},
	{name: "sum", signature: "<a<n>:n>", implementation: builtinSum},
	{name: "type", signature: "<x:s>", implementation: builtinType},
	{name: "distinct", signature: "<x:x>", implementation: builtinDistinct},
	{name: "each", signature: "<o-f:a>", implementation: builtinEach},
	{name: "join", signature: "<a<s>s?:s>", implementation: builtinJoin},
	{name: "keys", signature: "<x-:a<s>>", implementation: builtinKeys},
	{name: "lookup", signature: "<x-s:x>", implementation: builtinLookup},
	{name: "merge", signature: "<a<o>:o>", implementation: builtinMerge},
	{name: "reverse", signature: "<a:a>", implementation: builtinReverse},
	{name: "shuffle", signature: "<a:a>", implementation: builtinShuffle},
	{name: "sift", signature: "<o-f?:o>", implementation: builtinSift},
	{name: "sort", signature: "<af?:a>", implementation: builtinSort},
	{name: "spread", signature: "<x-:a<o>>", implementation: builtinSpread},
	{name: "zip", signature: "<a+>", implementation: builtinZip},
}

func collectionCheck(st state) error {
	if st.runtime == nil {
		return nil
	}
	return st.runtime.check()
}

func collectionTypeError(name string) error {
	return runtimeError{code: "T0412", msg: "argument to function \"$" + name + "\" does not match its signature"}
}

func collectionValues(v any) []any {
	raw := items(v)
	values := make([]any, 0, len(raw))
	for _, item := range raw {
		if nested, ok := item.(sequence); ok {
			for _, nestedItem := range nested {
				values = append(values, collapse(nestedItem))
			}
			continue
		}
		values = append(values, collapse(item))
	}
	return values
}

func collectionObject(v any) (map[string]any, bool) {
	switch object := collapse(v).(type) {
	case map[string]any:
		return object, true
	case value.OrderedObject:
		return object.Fields, true
	default:
		return nil, false
	}
}

func collectionObjectKeys(v any) ([]string, bool) {
	switch object := collapse(v).(type) {
	case map[string]any:
		return collectionSortedKeys(object), true
	case value.OrderedObject:
		return append([]string(nil), object.Order...), true
	default:
		return nil, false
	}
}

func collectionSortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return value.CanonicalObjectOrder(keys)
}

func invokeCollectionFunction(st state, fn any, args []any, current, parent any) (any, error) {
	call, ok := callable(fn)
	if !ok {
		return nil, functionTypeError("collection")
	}
	var err error
	args, err = collectionCallableArgs(call, args)
	if err != nil {
		return nil, err
	}
	callState := st
	callState.current = current
	callState.parent = parent
	callState.tail = false
	return call.invoke(callState, args)
}

func collectionCallableArgs(call callableValue, args []any) ([]any, error) {
	limit := -1
	switch fn := call.(type) {
	case *lambdaValue:
		if fn.signature == "" {
			limit = len(fn.params)
		} else if signature, err := parseFunctionSignature(fn.signature); err == nil {
			limit = len(signature.params)
		}
	case builtinValue:
		if fn.spec.signature != "" {
			if signature, err := parseFunctionSignature(fn.spec.signature); err == nil {
				limit = len(signature.params)
			}
		}
	}
	if limit >= 0 && limit > len(args) {
		return nil, functionArityError(call.callableName(), limit, len(args))
	}
	if limit >= 0 && len(args) > limit {
		return args[:limit], nil
	}
	return args, nil
}

func builtinAverage(st state, args []any) (any, error) {
	if err := collectionOneArgument("average", args); err != nil {
		return nil, err
	}
	values := collectionValues(args[0])
	if len(values) == 0 {
		return value.Undefined, nil
	}
	var total float64
	count := 0
	for _, item := range values {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		if value.IsUndefined(item) {
			continue
		}
		number, ok := strictNumeric(item)
		if !ok {
			return nil, collectionTypeError("average")
		}
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, nonFiniteCollectionError()
		}
		total += number
		count++
	}
	if count == 0 {
		return value.Undefined, nil
	}
	result := total / float64(count)
	if math.IsNaN(result) || math.IsInf(result, 0) {
		return nil, nonFiniteCollectionError()
	}
	return result, nil
}

func collectionOneArgument(name string, args []any) error {
	if len(args) != 1 {
		return runtimeError{code: "T0410", msg: "function \"$" + name + "\" expected one argument"}
	}
	return nil
}

func nonFiniteCollectionError() error {
	return runtimeError{code: "D1001", msg: "numeric result is not finite"}
}

func builtinCount(st state, args []any) (any, error) {
	if err := collectionCheck(st); err != nil {
		return nil, err
	}
	return float64(len(collectionValues(args[0]))), nil
}

func builtinLength(_ state, args []any) (any, error) {
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	text, ok := collapse(args[0]).(string)
	if !ok {
		return nil, collectionTypeError("length")
	}
	return float64(utf8.RuneCountInString(text)), nil
}

func builtinMax(st state, args []any) (any, error) {
	if err := collectionOneArgument("max", args); err != nil {
		return nil, err
	}
	return builtinExtreme(st, args[0], true, "max")
}

func builtinMin(st state, args []any) (any, error) {
	if err := collectionOneArgument("min", args); err != nil {
		return nil, err
	}
	return builtinExtreme(st, args[0], false, "min")
}

func builtinExtreme(st state, input any, maximum bool, name string) (any, error) {
	values := collectionValues(input)
	if len(values) == 0 {
		return value.Undefined, nil
	}
	var result float64
	found := false
	for _, item := range values {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		if value.IsUndefined(item) {
			continue
		}
		number, ok := strictNumeric(item)
		if !ok {
			return nil, collectionTypeError(name)
		}
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, nonFiniteCollectionError()
		}
		if !found || (maximum && number > result) || (!maximum && number < result) {
			result = number
			found = true
		}
	}
	if !found {
		return value.Undefined, nil
	}
	return result, nil
}

func builtinSum(st state, args []any) (any, error) {
	if err := collectionOneArgument("sum", args); err != nil {
		return nil, err
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	values := collectionValues(args[0])
	if len(values) == 0 {
		return 0.0, nil
	}
	var total float64
	for _, item := range values {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		if value.IsUndefined(item) {
			continue
		}
		number, ok := strictNumeric(item)
		if !ok {
			return nil, collectionTypeError("sum")
		}
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, nonFiniteCollectionError()
		}
		total += number
	}
	if math.IsNaN(total) || math.IsInf(total, 0) {
		return nil, nonFiniteCollectionError()
	}
	return total, nil
}

func builtinType(_ state, args []any) (any, error) {
	v := collapse(args[0])
	if value.IsUndefined(v) {
		return value.Undefined, nil
	}
	switch v.(type) {
	case nil:
		return "null", nil
	case bool:
		return "boolean", nil
	case string:
		return "string", nil
	case value.Array, []any, sequence:
		return "array", nil
	case map[string]any, value.OrderedObject:
		return "object", nil
	}
	if _, ok := callable(v); ok {
		return "function", nil
	}
	if _, ok := strictNumeric(v); ok {
		return "number", nil
	}
	return "unknown", nil
}

func builtinDistinct(st state, args []any) (any, error) {
	input := args[0]
	values := collectionValues(input)
	if len(values) == 0 && value.IsUndefined(input) {
		return value.Undefined, nil
	}
	unique := make([]any, 0, sequenceAllocationCapacity(len(values), st.runtime))
	for _, candidate := range values {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		found := false
		for _, existing := range unique {
			if err := collectionCheck(st); err != nil {
				return nil, err
			}
			if equal(candidate, existing) {
				found = true
				break
			}
		}
		if !found {
			if _, isSequence := input.(sequence); isSequence && st.runtime != nil {
				if err := st.runtime.checkSequenceLength(len(unique) + 1); err != nil {
					return nil, err
				}
			}
			unique = append(unique, candidate)
		}
	}
	switch input.(type) {
	case value.Array, []any, sequence:
		return value.Array{Items: unique}, nil
	default:
		if len(unique) == 0 {
			return value.Undefined, nil
		}
		return unique[0], nil
	}
}

func builtinEach(st state, args []any) (any, error) {
	if len(args) == 0 || len(args) > 2 {
		return nil, functionArityError("$each", 1, len(args))
	}
	var source, fn any
	if len(args) == 1 {
		if _, ok := callable(args[0]); !ok {
			return nil, functionArityError("$each", 2, len(args))
		}
		source, fn = st.current, args[0]
	} else {
		source, fn = args[0], args[1]
	}
	if _, ok := callable(fn); !ok {
		return nil, functionTypeError("each")
	}
	object, ok := collectionObject(source)
	if !ok {
		if value.IsUndefined(source) {
			return value.Undefined, nil
		}
		return nil, collectionTypeError("each")
	}
	keys, _ := collectionObjectKeys(source)
	callbackObject := collapse(source)
	result := make([]any, 0, sequenceAllocationCapacity(len(keys), st.runtime))
	for _, key := range keys {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		item, err := invokeCollectionFunction(st, fn, []any{object[key], key, callbackObject}, object[key], callbackObject)
		if err != nil {
			return nil, err
		}
		if !value.IsUndefined(item) {
			if st.runtime != nil {
				if err := st.runtime.checkSequenceLength(len(result) + 1); err != nil {
					return nil, err
				}
			}
			result = append(result, collapse(item))
		}
	}
	return value.Array{Items: result}, nil
}

func builtinJoin(st state, args []any) (any, error) {
	if len(args) == 0 {
		return nil, runtimeError{code: "T0410", msg: "function \"$join\" expected an argument"}
	}
	if len(args) > 2 {
		return nil, functionArityError("$join", 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	values := collectionValues(args[0])
	separator := ""
	if len(args) > 1 && !value.IsUndefined(args[1]) {
		separatorValue, ok := collapse(args[1]).(string)
		if !ok {
			return nil, runtimeError{code: "T0410", msg: "separator argument to function \"$join\" must be a string"}
		}
		separator = separatorValue
	}
	parts := make([]string, 0, len(values))
	for _, item := range values {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		text, ok := collapse(item).(string)
		if !ok {
			return nil, collectionTypeError("join")
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, separator), nil
}

func builtinKeys(st state, args []any) (any, error) {
	if len(args) > 1 {
		return nil, functionArityError("$keys", 1, len(args))
	}
	input := st.current
	if len(args) == 1 {
		input = args[0]
	}
	values := collectionValues(input)
	seen := make(map[string]struct{})
	keys := make([]string, 0)
	for _, item := range values {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		objectKeys, ok := collectionObjectKeys(item)
		if !ok {
			continue
		}
		for _, key := range objectKeys {
			if err := collectionCheck(st); err != nil {
				return nil, err
			}
			if _, exists := seen[key]; exists {
				continue
			}
			if st.runtime != nil {
				if err := st.runtime.checkSequenceLength(len(keys) + 1); err != nil {
					return nil, err
				}
			}
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	if len(seen) == 0 {
		return value.Undefined, nil
	}
	if err := collectionCheck(st); err != nil {
		return nil, err
	}
	return sequence(stringValues(keys)), nil
}

func stringValues(values []string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func builtinLookup(st state, args []any) (any, error) {
	if len(args) != 2 {
		return nil, functionArityError("$lookup", 2, len(args))
	}
	key, ok := collapse(args[1]).(string)
	if !ok {
		return nil, functionArityError("$lookup", 2, len(args))
	}
	result := make([]any, 0)
	sequenceLength := 0
	sequenceInput := false
	switch collapse(args[0]).(type) {
	case []any, value.Array, sequence:
		sequenceInput = true
	}
	for _, item := range collectionValues(args[0]) {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		object, ok := collectionObject(item)
		if !ok {
			continue
		}
		if value, exists := object[key]; exists {
			additional := itemsLength(value)
			if sequenceInput && st.runtime != nil {
				if err := st.runtime.checkSequenceLength(sequenceLength + additional); err != nil {
					return nil, err
				}
			}
			if sequenceInput {
				sequenceLength += additional
			}
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return value.Undefined, nil
	}
	if len(result) == 1 {
		return result[0], nil
	}
	return sequence(result), nil
}

func builtinMerge(st state, args []any) (any, error) {
	result := make(map[string]any)
	order := make([]string, 0)
	seen := make(map[string]struct{})
	for _, item := range collectionValues(args[0]) {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		object, ok := collectionObject(item)
		if !ok {
			return nil, collectionTypeError("merge")
		}
		keys, _ := collectionObjectKeys(item)
		for _, key := range keys {
			field := object[key]
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				order = append(order, key)
			}
			result[key] = deepClone(field)
		}
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	return value.OrderedObject{Fields: result, Order: value.CanonicalObjectOrder(order)}, nil
}

func builtinReverse(st state, args []any) (any, error) {
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	values := collectionValues(args[0])
	result := make([]any, len(values))
	for i := range values {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		result[len(values)-1-i] = values[i]
	}
	return value.Array{Items: result}, nil
}

func builtinShuffle(st state, args []any) (any, error) {
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	values := collectionValues(args[0])
	result := append([]any(nil), values...)
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := len(result) - 1; i > 0; i-- {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		j := random.Intn(i + 1)
		result[i], result[j] = result[j], result[i]
	}
	return value.Array{Items: result}, nil
}

func builtinSift(st state, args []any) (any, error) {
	if len(args) == 0 || len(args) > 2 {
		return nil, functionArityError("$sift", 1, len(args))
	}
	var source, fn any
	if len(args) == 1 {
		source, fn = st.current, args[0]
	} else {
		source, fn = args[0], args[1]
	}
	if _, ok := callable(fn); !ok {
		return nil, functionTypeError("sift")
	}
	object, ok := collectionObject(source)
	if !ok {
		if value.IsUndefined(source) {
			return value.Undefined, nil
		}
		return nil, collectionTypeError("sift")
	}
	result := make(map[string]any)
	resultOrder := make([]string, 0, len(object))
	keys, _ := collectionObjectKeys(source)
	callbackObject := collapse(source)
	for _, key := range keys {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		keep, err := invokeCollectionFunction(st, fn, []any{object[key], key, callbackObject}, object[key], callbackObject)
		if err != nil {
			return nil, err
		}
		if ebv(keep) {
			result[key] = object[key]
			resultOrder = append(resultOrder, key)
		}
	}
	if len(result) == 0 {
		return value.Undefined, nil
	}
	return value.OrderedObject{Fields: result, Order: value.CanonicalObjectOrder(resultOrder)}, nil
}

func builtinSort(st state, args []any) (any, error) {
	if len(args) == 0 || len(args) > 2 {
		return nil, functionArityError("$sort", 1, len(args))
	}
	if value.IsUndefined(args[0]) {
		return value.Undefined, nil
	}
	values := collectionValues(args[0])
	result := append([]any(nil), values...)
	var comparator callableValue
	if len(args) == 2 {
		var ok bool
		comparator, ok = callable(args[1])
		if !ok {
			return nil, functionTypeError("sort")
		}
	}
	var sortErr error
	sort.SliceStable(result, func(i, j int) bool {
		if sortErr != nil {
			return false
		}
		if err := collectionCheck(st); err != nil {
			sortErr = err
			return false
		}
		if comparator != nil {
			value, err := invokeCollectionFunction(st, comparator, []any{result[j], result[i]}, result[j], args[0])
			if err != nil {
				sortErr = err
				return false
			}
			boolean, ok := collapse(value).(bool)
			if !ok {
				sortErr = collectionTypeError("sort")
				return false
			}
			return boolean
		}
		left, right := collapse(result[i]), collapse(result[j])
		if _, ok := left.(string); ok {
			if _, ok := right.(string); !ok {
				sortErr = runtimeError{code: "D3070", msg: "incompatible values for sort"}
				return false
			}
			return left.(string) < right.(string)
		}
		leftNumber, leftOK := strictNumeric(left)
		rightNumber, rightOK := strictNumeric(right)
		if !leftOK || !rightOK {
			sortErr = runtimeError{code: "D3070", msg: "incompatible values for sort"}
			return false
		}
		return leftNumber < rightNumber

	})
	if sortErr != nil {
		return nil, sortErr
	}
	return value.Array{Items: result}, nil
}

func builtinSpread(st state, args []any) (any, error) {
	input := collapse(args[0])
	if value.IsUndefined(input) {
		return value.Undefined, nil
	}
	if text, ok := input.(string); ok {
		return text, nil
	}
	if _, ok := callable(input); ok {
		return input, nil
	}
	values := collectionValues(input)
	result := make([]any, 0)
	for _, item := range values {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		object, ok := collectionObject(item)
		if !ok {
			continue
		}
		keys, _ := collectionObjectKeys(item)
		for _, key := range keys {
			if err := collectionCheck(st); err != nil {
				return nil, err
			}
			if st.runtime != nil {
				if err := st.runtime.checkSequenceLength(len(result) + 1); err != nil {
					return nil, err
				}
			}
			result = append(result, map[string]any{key: object[key]})
		}
	}
	if len(result) == 0 {
		return value.Undefined, nil
	}
	return sequence(result), nil
}

func builtinZip(st state, args []any) (any, error) {
	if len(args) == 0 {
		return nil, functionArityError("$zip", 1, 0)
	}
	columns := make([][]any, len(args))
	rowCount := -1
	for i, arg := range args {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		columns[i] = collectionValues(arg)
		if rowCount < 0 || len(columns[i]) < rowCount {
			rowCount = len(columns[i])
		}
	}
	if rowCount < 0 {
		rowCount = 0
	}
	rows := make([]any, rowCount)
	for row := 0; row < rowCount; row++ {
		if err := collectionCheck(st); err != nil {
			return nil, err
		}
		itemsAtRow := make([]any, len(columns))
		for column := range columns {
			itemsAtRow[column] = columns[column][row]
		}
		rows[row] = value.Array{Items: itemsAtRow}
	}
	return value.Array{Items: rows}, nil
}
