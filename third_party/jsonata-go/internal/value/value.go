// Package value contains the evaluator's private JSONata value model.
package value

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"reflect"
	"slices"
)

// Undefined is deliberately distinct from JSON null. It is never returned by
// the public API; callers observe it as ErrUndefined when it is the result.
type undefined struct{}

var Undefined any = undefined{}

// Sequence is JSONata's transient path sequence. Unlike an Array, a
// singleton Sequence may collapse at an expression boundary and its members
// may be flattened by a path step.
type Sequence []any

// Array is an explicit JSONata/JSON array. Arrays remain grouped during path
// evaluation. Keep forces a singleton array to remain an array at the public
// expression boundary (the semantics of the explicit [] operator).
type Array struct {
	Items []any
	Keep  bool
}

// OrderedObject is an evaluator-only object representation. JSON objects are
// semantically unordered, but JSONata's stringification preserves the source
// order of constructed object fields. Fields remains a map for normal object
// lookup while Order carries the serialization order.
type OrderedObject struct {
	Fields map[string]any
	Order  []string
}

// DecodeOptions controls optional cooperative checks and nesting bounds while
// decoding one JSON document. The compatibility DecodeJSON path leaves these
// fields unset and retains the standard decoder behavior.
type DecodeOptions struct {
	Check    func() error
	MaxDepth int
}

// DecodeJSON decodes one JSON value while retaining object member order.
// JSONata exposes that order through $keys and string serialization.
func DecodeJSON(data []byte) (any, error) {
	return decodeJSON(bytes.NewReader(data), DecodeOptions{})
}

// DecodeJSONWithOptions decodes one JSON document while invoking Check before
// each input read. This keeps cancellation and operation limits synchronous
// with parsing, before the complete private value graph is materialized.
func DecodeJSONWithOptions(data []byte, options DecodeOptions) (any, error) {
	reader := &checkedReader{reader: bytes.NewReader(data), check: options.Check}
	return decodeJSON(reader, options)
}

func decodeJSON(reader io.Reader, options DecodeOptions) (any, error) {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	decoded, err := decodeValue(decoder, 1, options.MaxDepth)
	if err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("jsonata: trailing JSON value")
	} else if err != io.EOF {
		return nil, err
	}
	return decoded, nil
}

type checkedReader struct {
	reader io.Reader
	check  func() error
}

func (r *checkedReader) Read(p []byte) (int, error) {
	if r.check != nil {
		if err := r.check(); err != nil {
			return 0, err
		}
	}
	return r.reader.Read(p)
}

func decodeValue(decoder *json.Decoder, depth, maxDepth int) (any, error) {
	if maxDepth > 0 && depth > maxDepth {
		return nil, ErrNormalizationDepth
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		fields := make(map[string]any)
		order := make([]string, 0)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("jsonata: object key is not a string")
			}
			item, err := decodeValue(decoder, depth+1, maxDepth)
			if err != nil {
				return nil, err
			}
			if _, exists := fields[key]; !exists {
				order = append(order, key)
			}
			fields[key] = item
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return OrderedObject{Fields: fields, Order: canonicalObjectOrderOwned(order)}, nil
	case '[':
		items := make([]any, 0)
		for decoder.More() {
			item, err := decodeValue(decoder, depth+1, maxDepth)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return Array{Items: items}, nil
	default:
		return nil, fmt.Errorf("jsonata: unexpected JSON delimiter %q", delimiter)
	}
}

// FromJSON converts ordinary Go JSON values to the evaluator's private value
// model without retaining references to caller-owned slices or maps.
func FromJSON(v any) any {
	switch x := v.(type) {
	case Array:
		items := make([]any, len(x.Items))
		for i, item := range x.Items {
			items[i] = FromJSON(item)
		}
		return Array{Items: items, Keep: x.Keep}
	case OrderedObject:
		fields := make(map[string]any, len(x.Fields))
		for key, item := range x.Fields {
			fields[key] = FromJSON(item)
		}
		return OrderedObject{Fields: fields, Order: append([]string(nil), x.Order...)}
	case []any:
		items := make([]any, len(x))
		for i, item := range x {
			items[i] = FromJSON(item)
		}
		return Array{Items: items}
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, item := range x {
			out[key] = FromJSON(item)
		}
		return out
	default:
		return v
	}
}

func IsUndefined(v any) bool {
	_, ok := v.(undefined)
	return ok
}

// CanonicalObjectOrder applies ECMAScript own-property enumeration order:
// array-index keys first in numeric order, followed by other keys in their
// insertion order. JSONata inherits this behavior from JavaScript objects.
func CanonicalObjectOrder(keys []string) []string {
	return canonicalObjectOrder(keys, false)
}

// canonicalObjectOrderOwned may return keys unchanged. The caller transfers
// ownership and must not retain or mutate the input after this call.
func canonicalObjectOrderOwned(keys []string) []string {
	return canonicalObjectOrder(keys, true)
}

func canonicalObjectOrder(keys []string, owned bool) []string {
	type indexedKey struct {
		name  string
		index uint32
	}

	indexCount := 0
	canonical := true
	seenOther := false
	var previous uint32
	havePrevious := false
	for _, key := range keys {
		index, ok := parseArrayIndex(key)
		if !ok {
			seenOther = true
			continue
		}
		indexCount++
		if seenOther || havePrevious && index < previous {
			canonical = false
		}
		previous = index
		havePrevious = true
	}
	if canonical {
		if owned {
			return keys
		}
		order := make([]string, len(keys))
		copy(order, keys)
		return order
	}

	indexed := make([]indexedKey, 0, indexCount)
	for _, key := range keys {
		if index, ok := parseArrayIndex(key); ok {
			indexed = append(indexed, indexedKey{name: key, index: index})
		}
	}
	slices.SortFunc(indexed, func(a, b indexedKey) int {
		switch {
		case a.index < b.index:
			return -1
		case a.index > b.index:
			return 1
		default:
			return 0
		}
	})
	order := make([]string, 0, len(keys))
	for _, key := range indexed {
		order = append(order, key.name)
	}
	for _, key := range keys {
		if _, ok := parseArrayIndex(key); !ok {
			order = append(order, key)
		}
	}
	return order
}

func parseArrayIndex(key string) (uint32, bool) {
	if key == "" || len(key) > 10 || (key[0] == '0' && len(key) != 1) {
		return 0, false
	}

	const maxArrayIndex = uint64(math.MaxUint32 - 1)
	var index uint64
	for i := range len(key) {
		digit := key[i]
		if digit < '0' || digit > '9' {
			return 0, false
		}
		value := uint64(digit - '0')
		if index > (maxArrayIndex-value)/10 {
			return 0, false
		}
		index = index*10 + value
	}
	return uint32(index), true
}

// Public converts evaluator values into ordinary JSON-compatible Go values.
// Undefined members are omitted from objects and arrays, matching JSONata's
// empty-sequence construction behavior.
func Public(v any) (any, bool) {
	if IsUndefined(v) {
		return nil, false
	}
	if n, ok := v.(json.Number); ok {
		f, err := n.Float64()
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, false
		}
		return f, true
	}
	switch x := v.(type) {
	case nil, string, bool, float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return x, true
	case Array:
		out := make([]any, 0, len(x.Items))
		for _, item := range x.Items {
			if p, ok := Public(item); ok {
				out = append(out, p)
			}
		}
		return out, true
	case OrderedObject:
		out := make(map[string]any, len(x.Fields))
		for key, item := range x.Fields {
			if p, ok := Public(item); ok {
				out[key] = p
			}
		}
		return out, true
	case Sequence:
		// Sequences must be collapsed before the public boundary. Keeping this
		// fallback prevents private sequence types from leaking if a future
		// evaluator path misses normalization.
		if len(x) == 1 {
			return Public(x[0])
		}
		out := make([]any, 0, len(x))
		for _, item := range x {
			if p, ok := Public(item); ok {
				out = append(out, p)
			}
		}
		return out, true
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			if p, ok := Public(item); ok {
				out = append(out, p)
			}
		}
		return out, true
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			if p, ok := Public(item); ok {
				out[k] = p
			}
		}
		return out, true
	}
	return publicReflect(reflect.ValueOf(v))
}

func publicReflect(v reflect.Value) (any, bool) {
	if !v.IsValid() {
		return nil, true
	}
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil, true
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil, false
		}
		out := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			p, ok := Public(iter.Value().Interface())
			if ok {
				out[iter.Key().String()] = p
			}
		}
		return out, true
	case reflect.Slice, reflect.Array:
		out := make([]any, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			p, ok := Public(v.Index(i).Interface())
			if ok {
				out = append(out, p)
			}
		}
		return out, true
	case reflect.String:
		return v.String(), true
	case reflect.Bool:
		return v.Bool(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(v.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(v.Uint()), true
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		return f, !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return nil, false
}
