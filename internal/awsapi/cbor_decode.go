package awsapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	mathbits "math/bits"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/smithy-go/encoding/cbor"
	cborframing "github.com/fxamacker/cbor/v2"

	"stackd/internal/awscatalog"
)

func decodeCBOR(service awscatalog.Service, operation awscatalog.Operation, body []byte, out any) error {
	destination := reflect.ValueOf(out)
	if operation.Input == "smithy.api#Unit" {
		if len(body) != 0 {
			return &ValidationError{Reason: "Unit input must not contain a body"}
		}
		destination.Elem().SetZero()
		return nil
	}
	// Smithy's decoder does not report trailing bytes or overflowing declared
	// collection lengths. Use the maintained framing checker at the wire edge.
	if err := cborframing.Wellformed(body); err != nil {
		return &ValidationError{Reason: "malformed CBOR input"}
	}
	value, err := cbor.Decode(body)
	if err != nil {
		// Library diagnostics can contain input values; never surface them.
		return &ValidationError{Reason: "malformed CBOR input"}
	}
	bound := reflect.New(destination.Elem().Type()).Elem()
	if err := cborDecodeValue(service, operation.Input, value, bound, "", awscatalog.Constraints{}); err != nil {
		return err
	}
	destination.Elem().Set(bound)
	return nil
}

func cborDecodeNull(value cbor.Value) bool {
	switch value.(type) {
	case nil, *cbor.Nil, *cbor.Undefined:
		return true
	default:
		return false
	}
}

func cborDecodeValue(service awscatalog.Service, id awscatalog.ShapeID, value cbor.Value, destination reflect.Value, path string, overrides awscatalog.Constraints) error {
	shape, ok := service.Shape(id)
	if !ok {
		return fmt.Errorf("missing generated shape %s", id)
	}
	if shape.Kind == "document" || shape.Kind == "bigInteger" || shape.Kind == "bigDecimal" || (shape.Streaming && shape.Kind != "blob") {
		return fmt.Errorf("%w: CBOR shape %s (%s)", ErrUnsupportedBinding, id, shape.Kind)
	}
	invalid := func(reason string) error { return &ValidationError{Path: path, Reason: reason} }
	if cborDecodeNull(value) {
		return invalid("value must not be null")
	}
	if !destination.IsValid() || !destination.CanSet() {
		return fmt.Errorf("missing generated destination for %s", id)
	}
	for destination.Kind() == reflect.Pointer {
		destination.Set(reflect.New(destination.Type().Elem()))
		destination = destination.Elem()
	}
	constraints := mergeConstraints(shape.Constraints, overrides)
	switch shape.Kind {
	case "structure", "union":
		object, ok := value.(cbor.Map)
		if !ok {
			return invalid("expected an object")
		}
		fields, err := smithyFields(destination, id)
		if err != nil {
			return err
		}
		members := 0
		for _, member := range shape.Members {
			memberPath := joinPath(path, member.Name)
			item := object[member.Name]
			if cborDecodeNull(item) {
				defaultValue := member.Default
				if defaultValue == "" && shape.Kind == "structure" {
					target, _ := service.Shape(member.Target)
					defaultValue = target.Default
				}
				if shape.Kind == "structure" && defaultValue != "" && defaultValue != "null" {
					item, err = cborDecodeDefault(service, member.Target, defaultValue)
					if err != nil {
						return err
					}
				} else if member.Required {
					return &ValidationError{Path: memberPath, Reason: "required member is missing", Constraint: "required"}
				} else {
					continue
				}
			}
			if err := cborDecodeValue(service, member.Target, item, fields[member.Name], memberPath, member.Constraints); err != nil {
				return err
			}
			members++
		}
		// Unmodeled fields, including __type, do not select a union variant.
		if shape.Kind == "union" && members != 1 {
			return invalid("union must contain exactly one member")
		}
	case "list", "set":
		list, ok := value.(cbor.List)
		if !ok {
			return invalid("expected an array")
		}
		if destination.Kind() != reflect.Slice {
			return fmt.Errorf("expected generated collection %s", id)
		}
		if err := checkBounds(constraints.Length, strconv.Itoa(len(list)), path, "length"); err != nil {
			return err
		}
		destination.Set(reflect.MakeSlice(destination.Type(), len(list), len(list)))
		unique := constraints.UniqueItems || shape.Kind == "set"
		for i, item := range list {
			if !shape.Sparse || !cborDecodeNull(item) {
				if err := cborDecodeValue(service, shape.Member.Target, item, destination.Index(i), fmt.Sprintf("%s[%d]", path, i), shape.Member.Constraints); err != nil {
					return err
				}
			}
			if unique {
				for j := range i {
					if cborDecodeEqual(destination.Index(i), destination.Index(j)) {
						return invalid("collection values must be unique")
					}
				}
			}
		}
	case "map":
		object, ok := value.(cbor.Map)
		if !ok {
			return invalid("expected an object")
		}
		if destination.Kind() != reflect.Map {
			return fmt.Errorf("expected generated map %s", id)
		}
		if err := checkBounds(constraints.Length, strconv.Itoa(len(object)), path, "length"); err != nil {
			return err
		}
		destination.Set(reflect.MakeMapWithSize(destination.Type(), len(object)))
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			mapKey := reflect.New(destination.Type().Key()).Elem()
			if err := cborDecodeValue(service, shape.Key.Target, cbor.String(key), mapKey, path+"[key]", shape.Key.Constraints); err != nil {
				return err
			}
			item := reflect.New(destination.Type().Elem()).Elem()
			if !shape.Sparse || !cborDecodeNull(object[key]) {
				if err := cborDecodeValue(service, shape.Value.Target, object[key], item, path+"[value]", shape.Value.Constraints); err != nil {
					return err
				}
			}
			destination.SetMapIndex(mapKey, item)
		}
	case "string", "enum":
		text, ok := value.(cbor.String)
		if !ok {
			return invalid("expected a string")
		}
		if !utf8.ValidString(string(text)) {
			return invalid("expected a UTF-8 string")
		}
		if destination.Kind() != reflect.String {
			return fmt.Errorf("expected generated string %s", id)
		}
		if err := checkBounds(constraints.Length, strconv.Itoa(utf8.RuneCountInString(string(text))), path, "length"); err != nil {
			return err
		}
		if constraints.Pattern != "" {
			matches, err := matchPattern(constraints.Pattern, string(text))
			if err != nil {
				return fmt.Errorf("evaluate %s pattern: %w", id, err)
			}
			if !matches {
				return &ValidationError{Path: path, Reason: "value does not match the modeled pattern", Constraint: "pattern"}
			}
		}
		if (shape.Kind == "enum" || len(shape.Enum) != 0) && !enumContains(shape.Enum, string(text)) {
			return &ValidationError{Path: path, Reason: "value is not a modeled enum member", Constraint: "enum", EnumValue: string(text)}
		}
		destination.SetString(string(text))
	case "blob":
		blob, ok := value.(cbor.Slice)
		if !ok {
			return invalid("expected a byte string")
		}
		if destination.Kind() != reflect.Slice || destination.Type().Elem().Kind() != reflect.Uint8 {
			return fmt.Errorf("expected generated blob %s", id)
		}
		if err := checkBounds(constraints.Length, strconv.Itoa(len(blob)), path, "length"); err != nil {
			return err
		}
		// Keep an explicit empty blob distinct from an omitted member, and do
		// not retain an alias into the caller's request buffer.
		data := make([]byte, len(blob))
		copy(data, blob)
		destination.SetBytes(data)
	case "boolean":
		boolean, ok := value.(cbor.Bool)
		if !ok {
			return invalid("expected a boolean")
		}
		if destination.Kind() != reflect.Bool {
			return fmt.Errorf("expected generated boolean %s", id)
		}
		destination.SetBool(bool(boolean))
	case "byte", "short", "integer", "long", "intEnum":
		number, err := cbor.AsInt64(value)
		bits := 64
		switch shape.Kind {
		case "byte":
			bits = 8
		case "short":
			bits = 16
		case "integer", "intEnum":
			bits = 32
		}
		if err != nil || (bits < 64 && (number < -(int64(1)<<(bits-1)) || number >= int64(1)<<(bits-1))) {
			return invalid("expected an integer in the modeled type range")
		}
		text := strconv.FormatInt(number, 10)
		if err := checkBounds(constraints.Range, text, path, "range"); err != nil {
			return err
		}
		if shape.Kind == "intEnum" && !enumContains(shape.Enum, text) {
			return invalid("value is not a modeled enum member")
		}
		if destination.Kind() < reflect.Int || destination.Kind() > reflect.Int64 || destination.OverflowInt(number) {
			return fmt.Errorf("expected generated integer %s", id)
		}
		destination.SetInt(number)
	case "float", "double":
		number, ok := cborDecodeNumber(value)
		if !ok {
			return invalid("expected a number")
		}
		bits := 64
		if shape.Kind == "float" {
			bits = 32
			if !math.IsInf(number, 0) && (number > math.MaxFloat32 || number < -math.MaxFloat32) {
				return invalid("number is outside the modeled type range")
			}
		}
		precision := 53
		if bits == 32 {
			precision = 24
		}
		var magnitude uint64
		switch value := value.(type) {
		case cbor.Uint:
			magnitude = uint64(value)
		case cbor.NegInt:
			// NegInt(0) denotes -2^64, which is exactly representable.
			magnitude = uint64(value)
		}
		if magnitude != 0 && mathbits.Len64(magnitude)-mathbits.TrailingZeros64(magnitude) > precision {
			return invalid("integer cannot be represented exactly in the modeled floating-point type")
		}
		if err := checkBounds(constraints.Range, strconv.FormatFloat(number, 'g', -1, 64), path, "range"); err != nil {
			return err
		}
		if (destination.Kind() != reflect.Float32 && destination.Kind() != reflect.Float64) || destination.Type().Bits() != bits {
			return fmt.Errorf("expected generated floating-point number %s", id)
		}
		destination.SetFloat(number)
	case "timestamp":
		tag, ok := value.(*cbor.Tag)
		if !ok || tag.ID != 1 {
			return invalid("expected an epoch-tagged timestamp")
		}
		var timestamp time.Time
		switch tag.Value.(type) {
		case cbor.Uint, cbor.NegInt:
			seconds, err := cbor.AsInt64(tag.Value)
			if err != nil {
				return invalid("timestamp is out of range")
			}
			timestamp = time.Unix(seconds, 0).UTC()
		default:
			seconds, ok := cborDecodeNumber(tag.Value)
			if !ok || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < -0x1p63 || seconds >= 0x1p63 {
				return invalid("timestamp is out of range")
			}
			whole, fraction := math.Modf(seconds)
			timestamp = time.Unix(int64(whole), int64(math.Round(fraction*1000))*int64(time.Millisecond)).UTC()
		}
		if destination.Type() != reflect.TypeFor[time.Time]() {
			return fmt.Errorf("expected generated timestamp %s", id)
		}
		destination.Set(reflect.ValueOf(timestamp))
	default:
		return fmt.Errorf("unsupported generated shape kind %s", shape.Kind)
	}
	return nil
}

// The library's float coercers exclude some exactly representable integers
// and Float64-to-Float32 conversions. The modeled destination decides the range.
func cborDecodeNumber(value cbor.Value) (float64, bool) {
	switch value := value.(type) {
	case cbor.Float32:
		return float64(value), true
	case cbor.Float64:
		return float64(value), true
	case cbor.Uint:
		return float64(value), true
	case cbor.NegInt:
		if value == 0 {
			return -0x1p64, true
		}
		return -float64(value), true
	default:
		return 0, false
	}
}

// Defaults are JSON literals in the generated model, not wire JSON. Only
// scalar defaults and empty collections are legal Smithy default values.
func cborDecodeDefault(service awscatalog.Service, id awscatalog.ShapeID, text string) (cbor.Value, error) {
	shape, ok := service.Shape(id)
	if !ok {
		return nil, fmt.Errorf("missing generated shape %s", id)
	}
	invalid := func() (cbor.Value, error) { return nil, fmt.Errorf("invalid generated default for %s", id) }
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var value any
	if !json.Valid([]byte(text)) || decoder.Decode(&value) != nil {
		return invalid()
	}
	switch value := value.(type) {
	case nil:
		return &cbor.Nil{}, nil
	case bool:
		return cbor.Bool(value), nil
	case string:
		if shape.Kind == "blob" {
			blob, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return invalid()
			}
			return cbor.Slice(blob), nil
		}
		return cbor.String(value), nil
	case json.Number:
		if shape.Kind == "float" || shape.Kind == "double" || shape.Kind == "timestamp" {
			number, err := strconv.ParseFloat(value.String(), 64)
			if err != nil {
				return invalid()
			}
			if shape.Kind == "timestamp" {
				return &cbor.Tag{ID: 1, Value: cbor.Float64(number)}, nil
			}
			return cbor.Float64(number), nil
		}
		number, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil {
			return invalid()
		}
		if number < 0 {
			return cbor.NegInt(uint64(-(number + 1)) + 1), nil
		}
		return cbor.Uint(number), nil
	case []any:
		if len(value) == 0 {
			return cbor.List{}, nil
		}
	case map[string]any:
		if len(value) == 0 {
			return cbor.Map{}, nil
		}
	}
	return invalid()
}

// Compare decoded values, not their wire representation: integer/float widths,
// field ordering, defaults, signed zero and null/undefined must not evade sets.
func cborDecodeEqual(left, right reflect.Value) bool {
	if left.Type() != right.Type() {
		return false
	}
	switch left.Kind() {
	case reflect.Pointer:
		if left.IsNil() || right.IsNil() {
			return left.IsNil() == right.IsNil()
		}
		return cborDecodeEqual(left.Elem(), right.Elem())
	case reflect.Float32, reflect.Float64:
		a, b := left.Float(), right.Float()
		return a == b || (math.IsNaN(a) && math.IsNaN(b))
	case reflect.Slice, reflect.Array:
		if left.Kind() == reflect.Slice && left.IsNil() != right.IsNil() {
			return false
		}
		if left.Len() != right.Len() {
			return false
		}
		for i := range left.Len() {
			if !cborDecodeEqual(left.Index(i), right.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Map:
		if left.IsNil() != right.IsNil() || left.Len() != right.Len() {
			return false
		}
		iter := left.MapRange()
		for iter.Next() {
			value := right.MapIndex(iter.Key())
			if !value.IsValid() || !cborDecodeEqual(iter.Value(), value) {
				return false
			}
		}
		return true
	case reflect.Struct:
		if left.Type() == reflect.TypeFor[time.Time]() {
			return left.Interface().(time.Time).Equal(right.Interface().(time.Time))
		}
		for i := range left.NumField() {
			if !cborDecodeEqual(left.Field(i), right.Field(i)) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(left.Interface(), right.Interface())
	}
}
