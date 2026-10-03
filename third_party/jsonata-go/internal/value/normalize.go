package value

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
)

var (
	// ErrCyclicValue identifies a reference cycle in an input container.
	ErrCyclicValue = errors.New("jsonata: cyclic input value")
	// ErrNormalizationDepth identifies an input that exceeds its nesting bound.
	ErrNormalizationDepth = errors.New("jsonata: input nesting exceeds the maximum depth")
	// ErrUnsupportedValue identifies a Go value that has no JSON representation.
	ErrUnsupportedValue = errors.New("jsonata: input contains an unsupported Go value")
	// ErrNonFiniteValue identifies a number that JSON cannot represent.
	ErrNonFiniteValue = errors.New("jsonata: input contains a non-finite number")
)

// NormalizeMapper maps evaluator-owned values before JSON normalization. A
// terminal result is preserved without reflection, which keeps callables and
// undefined sentinels private to the evaluator.
type NormalizeMapper func(any) (mapped any, terminal bool, err error)

// FromJSONSafe converts ordinary Go JSON values without retaining caller-owned
// containers. The optional check shares an evaluator's cancellation and
// operation budget. A positive maxDepth bounds nested arrays and objects.
func FromJSONSafe(v any, maxDepth int, check func() error) (any, error) {
	return FromJSONSafeWithMapper(v, maxDepth, check, nil)
}

// FromJSONSafeWithMapper applies mapper to every value before normalizing its
// containers. It lets evaluator-specific leaf values remain outside this
// package while retaining the same cycle and resource bounds.
func FromJSONSafeWithMapper(v any, maxDepth int, check func() error, mapper NormalizeMapper) (any, error) {
	return fromJSONSafe(v, 1, maxDepth, check, mapper, make(map[normalizationVisit]struct{}))
}

type normalizationVisit struct {
	kind  reflect.Kind
	type_ reflect.Type
	ptr   uintptr
}

func fromJSONSafe(v any, depth, maxDepth int, check func() error, mapper NormalizeMapper, visiting map[normalizationVisit]struct{}) (any, error) {
	if check != nil {
		if err := check(); err != nil {
			return nil, err
		}
	}
	if maxDepth > 0 && depth > maxDepth {
		return nil, ErrNormalizationDepth
	}
	if mapper != nil {
		mapped, terminal, err := mapper(v)
		if err != nil {
			return nil, err
		}
		if terminal {
			return mapped, nil
		}
		v = mapped
	}

	switch current := v.(type) {
	case nil, bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return current, nil
	case float32:
		if number := float64(current); math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, ErrNonFiniteValue
		}
		return current, nil
	case float64:
		if math.IsNaN(current) || math.IsInf(current, 0) {
			return nil, ErrNonFiniteValue
		}
		return current, nil
	case json.Number:
		number, err := current.Float64()
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, ErrNonFiniteValue
		}
		return current, nil
	case undefined:
		return current, nil
	case Array:
		visit, err := beginNormalizationVisit(current.Items, visiting)
		if err != nil {
			return nil, err
		}
		defer endNormalizationVisit(visit, visiting)
		items, err := normalizeJSONItems(current.Items, depth, maxDepth, check, mapper, visiting)
		if err != nil {
			return nil, err
		}
		return Array{Items: items, Keep: current.Keep}, nil
	case OrderedObject:
		visit, err := beginNormalizationVisit(current.Fields, visiting)
		if err != nil {
			return nil, err
		}
		defer endNormalizationVisit(visit, visiting)
		fields, err := normalizeJSONFields(current.Fields, depth, maxDepth, check, mapper, visiting)
		if err != nil {
			return nil, err
		}
		return OrderedObject{Fields: fields, Order: append([]string(nil), current.Order...)}, nil
	case Sequence:
		visit, err := beginNormalizationVisit(current, visiting)
		if err != nil {
			return nil, err
		}
		defer endNormalizationVisit(visit, visiting)
		items, err := normalizeJSONItems([]any(current), depth, maxDepth, check, mapper, visiting)
		if err != nil {
			return nil, err
		}
		return Sequence(items), nil
	case []any:
		if current == nil {
			return nil, nil
		}
		visit, err := beginNormalizationVisit(current, visiting)
		if err != nil {
			return nil, err
		}
		defer endNormalizationVisit(visit, visiting)
		items, err := normalizeJSONItems(current, depth, maxDepth, check, mapper, visiting)
		if err != nil {
			return nil, err
		}
		return Array{Items: items}, nil
	case map[string]any:
		if current == nil {
			return nil, nil
		}
		visit, err := beginNormalizationVisit(current, visiting)
		if err != nil {
			return nil, err
		}
		defer endNormalizationVisit(visit, visiting)
		return normalizeJSONFields(current, depth, maxDepth, check, mapper, visiting)
	}
	return normalizeReflectedJSONValue(reflect.ValueOf(v), depth, maxDepth, check, mapper, visiting)
}

func normalizeJSONItems(input []any, depth, maxDepth int, check func() error, mapper NormalizeMapper, visiting map[normalizationVisit]struct{}) ([]any, error) {
	items := make([]any, 0, len(input))
	for _, item := range input {
		normalized, err := fromJSONSafe(item, depth+1, maxDepth, check, mapper, visiting)
		if err != nil {
			return nil, err
		}
		items = append(items, normalized)
	}
	return items, nil
}

func normalizeJSONFields(input map[string]any, depth, maxDepth int, check func() error, mapper NormalizeMapper, visiting map[normalizationVisit]struct{}) (map[string]any, error) {
	fields := make(map[string]any, len(input))
	for key, item := range input {
		normalized, err := fromJSONSafe(item, depth+1, maxDepth, check, mapper, visiting)
		if err != nil {
			return nil, err
		}
		fields[key] = normalized
	}
	return fields, nil
}

func normalizeReflectedJSONValue(input reflect.Value, depth, maxDepth int, check func() error, mapper NormalizeMapper, visiting map[normalizationVisit]struct{}) (any, error) {
	if !input.IsValid() {
		return nil, nil
	}
	if !input.CanInterface() {
		return nil, ErrUnsupportedValue
	}
	switch input.Kind() {
	case reflect.Interface:
		if input.IsNil() {
			return nil, nil
		}
		if !input.Elem().CanInterface() {
			return nil, ErrUnsupportedValue
		}
		return fromJSONSafe(input.Elem().Interface(), depth, maxDepth, check, mapper, visiting)
	case reflect.Pointer:
		if input.IsNil() {
			return nil, nil
		}
		visit, err := beginNormalizationReflectVisit(input, visiting)
		if err != nil {
			return nil, err
		}
		defer endNormalizationVisit(visit, visiting)
		if !input.Elem().CanInterface() {
			return nil, ErrUnsupportedValue
		}
		return fromJSONSafe(input.Elem().Interface(), depth+1, maxDepth, check, mapper, visiting)
	case reflect.Map:
		if input.IsNil() {
			return nil, nil
		}
		if input.Type().Key().Kind() != reflect.String {
			return nil, ErrUnsupportedValue
		}
		visit, err := beginNormalizationReflectVisit(input, visiting)
		if err != nil {
			return nil, err
		}
		defer endNormalizationVisit(visit, visiting)
		fields := make(map[string]any, input.Len())
		iterator := input.MapRange()
		for iterator.Next() {
			item := iterator.Value()
			if !item.CanInterface() {
				return nil, ErrUnsupportedValue
			}
			normalized, err := fromJSONSafe(item.Interface(), depth+1, maxDepth, check, mapper, visiting)
			if err != nil {
				return nil, err
			}
			fields[iterator.Key().String()] = normalized
		}
		return fields, nil
	case reflect.Slice:
		if input.IsNil() {
			return nil, nil
		}
		visit, err := beginNormalizationReflectVisit(input, visiting)
		if err != nil {
			return nil, err
		}
		defer endNormalizationVisit(visit, visiting)
		return normalizeReflectedJSONItems(input, depth, maxDepth, check, mapper, visiting)
	case reflect.Array:
		return normalizeReflectedJSONItems(input, depth, maxDepth, check, mapper, visiting)
	case reflect.Bool:
		return input.Bool(), nil
	case reflect.String:
		return input.String(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return input.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return input.Uint(), nil
	case reflect.Float32, reflect.Float64:
		number := input.Float()
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, ErrNonFiniteValue
		}
		return number, nil
	default:
		return nil, ErrUnsupportedValue
	}
}

func normalizeReflectedJSONItems(input reflect.Value, depth, maxDepth int, check func() error, mapper NormalizeMapper, visiting map[normalizationVisit]struct{}) (Array, error) {
	items := make([]any, 0, input.Len())
	for index := 0; index < input.Len(); index++ {
		item := input.Index(index)
		if !item.CanInterface() {
			return Array{}, ErrUnsupportedValue
		}
		normalized, err := fromJSONSafe(item.Interface(), depth+1, maxDepth, check, mapper, visiting)
		if err != nil {
			return Array{}, err
		}
		items = append(items, normalized)
	}
	return Array{Items: items}, nil
}

func beginNormalizationVisit(input any, visiting map[normalizationVisit]struct{}) (normalizationVisit, error) {
	reflected := reflect.ValueOf(input)
	if !reflected.IsValid() || reflected.IsNil() {
		return normalizationVisit{}, nil
	}
	return beginNormalizationReflectVisit(reflected, visiting)
}

func beginNormalizationReflectVisit(reflected reflect.Value, visiting map[normalizationVisit]struct{}) (normalizationVisit, error) {
	visit := normalizationVisit{kind: reflected.Kind(), type_: reflected.Type(), ptr: reflected.Pointer()}
	if _, exists := visiting[visit]; exists {
		return normalizationVisit{}, ErrCyclicValue
	}
	visiting[visit] = struct{}{}
	return visit, nil
}

func endNormalizationVisit(visit normalizationVisit, visiting map[normalizationVisit]struct{}) {
	if visit.type_ != nil {
		delete(visiting, visit)
	}
}
