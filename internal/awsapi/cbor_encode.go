package awsapi

import (
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/aws/smithy-go/encoding/cbor"

	"stackd/internal/awscatalog"
)

// encodeCBORResponse follows RPCv2's Smithy member names and wire types, not
// JSON/XML names or HTTP bindings. Output presence belongs to service behavior;
// request constraints and enum membership do not constrain evolving responses.
func encodeCBORResponse(service awscatalog.Service, operation awscatalog.Operation, output any) ([]byte, error) {
	if operation.Output == "smithy.api#Unit" {
		return nil, nil
	}
	shape, ok := service.Shape(operation.Output)
	if !ok {
		return nil, fmt.Errorf("missing generated shape %s", operation.Output)
	}
	if shape.Kind != "structure" {
		return nil, fmt.Errorf("expected generated output structure %s", shape.ID)
	}
	value, err := cborEncodeStructure(service, shape, reflect.ValueOf(output))
	if err != nil {
		return nil, err
	}
	return cbor.Encode(value), nil
}

func cborEncodeValue(service awscatalog.Service, id awscatalog.ShapeID, value reflect.Value) (cbor.Value, error) {
	shape, ok := service.Shape(id)
	if !ok {
		return nil, fmt.Errorf("missing generated shape %s", id)
	}
	if shape.Streaming && shape.Kind != "blob" {
		return nil, fmt.Errorf("%w: RPCv2 CBOR event stream %s", ErrUnsupportedBinding, id)
	}
	switch shape.Kind {
	case "document", "bigInteger", "bigDecimal":
		return nil, fmt.Errorf("unsupported RPCv2 CBOR response shape %s (%s)", id, shape.Kind)
	}
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return &cbor.Nil{}, nil
		}
		value = value.Elem()
	}
	if !value.IsValid() || nilValue(value) {
		return &cbor.Nil{}, nil
	}
	switch shape.Kind {
	case "structure", "union":
		return cborEncodeStructure(service, shape, value)
	case "list", "set":
		if value.Kind() != reflect.Slice {
			return nil, outputTypeError(id, value)
		}
		items := make(cbor.List, value.Len())
		for i := range value.Len() {
			item, err := cborEncodeValue(service, shape.Member.Target, value.Index(i))
			if err != nil {
				return nil, fmt.Errorf("output %s[%d]: %w", id, i, err)
			}
			if _, null := item.(*cbor.Nil); null && !shape.Sparse {
				return nil, fmt.Errorf("null member in nonsparse output %s[%d]", id, i)
			}
			items[i] = item
		}
		return items, nil
	case "map":
		if value.Kind() != reflect.Map || value.Type().Key().Kind() != reflect.String {
			return nil, outputTypeError(id, value)
		}
		items := make(cbor.Map, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			item, err := cborEncodeValue(service, shape.Value.Target, iterator.Value())
			if err != nil {
				return nil, fmt.Errorf("output %s[%q]: %w", id, key, err)
			}
			if _, null := item.(*cbor.Nil); null && !shape.Sparse {
				return nil, fmt.Errorf("null member in nonsparse output %s[%q]", id, key)
			}
			items[key] = item
		}
		return items, nil
	case "timestamp":
		if !value.CanInterface() {
			return nil, outputTypeError(id, value)
		}
		stamp, ok := value.Interface().(time.Time)
		if !ok {
			return nil, outputTypeError(id, value)
		}
		// Drop submillisecond precision before conversion, without UnixNano or
		// UnixMilli overflow for timestamps outside their representable ranges.
		seconds, millis := stamp.Unix(), stamp.Nanosecond()/int(time.Millisecond)
		var epoch cbor.Value = cborEncodeInteger(seconds)
		if millis != 0 {
			epoch = cborEncodeFloat(float64(seconds) + float64(millis)/1e3)
		}
		return &cbor.Tag{ID: 1, Value: epoch}, nil
	case "blob":
		if value.Kind() != reflect.Slice || value.Type().Elem().Kind() != reflect.Uint8 {
			return nil, outputTypeError(id, value)
		}
		return cbor.Slice(value.Bytes()), nil
	case "string", "enum":
		if value.Kind() != reflect.String {
			return nil, outputTypeError(id, value)
		}
		return cbor.String(value.String()), nil
	case "boolean":
		if value.Kind() != reflect.Bool {
			return nil, outputTypeError(id, value)
		}
		return cbor.Bool(value.Bool()), nil
	case "byte", "short", "integer", "long", "intEnum":
		if !value.CanInt() {
			return nil, outputTypeError(id, value)
		}
		return cborEncodeInteger(value.Int()), nil
	case "float", "double":
		if !value.CanFloat() {
			return nil, outputTypeError(id, value)
		}
		return cborEncodeFloat(value.Float()), nil
	default:
		return nil, fmt.Errorf("unsupported RPCv2 CBOR response shape %s (%s)", id, shape.Kind)
	}
}

func cborEncodeStructure(service awscatalog.Service, shape awscatalog.Shape, value reflect.Value) (cbor.Value, error) {
	fields, err := smithyFields(value, shape.ID)
	if err != nil {
		return nil, err
	}
	object := make(cbor.Map, len(shape.Members))
	for _, member := range shape.Members {
		field, ok := fields[member.Name]
		if !ok {
			return nil, fmt.Errorf("output %s missing generated member %s", shape.ID, member.Name)
		}
		encoded, err := cborEncodeValue(service, member.Target, field)
		if err != nil {
			return nil, fmt.Errorf("output %s.%s: %w", shape.ID, member.Name, err)
		}
		if _, null := encoded.(*cbor.Nil); null {
			continue
		}
		object[member.Name] = encoded
	}
	if shape.Kind == "union" && len(object) != 1 {
		return nil, fmt.Errorf("output union %s must have one member", shape.ID)
	}
	return object, nil
}

func cborEncodeInteger(value int64) cbor.Value {
	if value >= 0 {
		return cbor.Uint(value)
	}
	// NegInt stores the magnitude; negate only after moving MinInt64 into
	// the signed range, then add the final unit using unsigned arithmetic.
	return cbor.NegInt(uint64(-(value + 1)) + 1)
}

func cborEncodeFloat(value float64) cbor.Value {
	// RPCv2 discourages float16. Use float32 only when it preserves the value,
	// including signed zero and infinities; NaN remains a native CBOR float.
	if float64(float32(value)) == value || math.IsNaN(value) {
		return cbor.Float32(value)
	}
	return cbor.Float64(value)
}
