package awsapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awscatalog"
)

// EncodeResponse serializes a generated output using its Smithy wire contract.
// Timestamps follow modeled formats (epoch seconds by default), blobs are base64, and present
// empty collections are retained. It never applies request constraints to AWS
// outputs, which can evolve independently of client-side validation rules.
// Service behavior owns field presence, except reviewed JSONResponseNull members
// whose nil values are explicitly null on the wire.
func EncodeResponse(service awscatalog.Service, operation awscatalog.Operation, output any) ([]byte, error) {
	if service.Protocol == awscatalog.RPCV2CBOR {
		return encodeCBORResponse(service, operation, output)
	}
	if service.Protocol == awscatalog.AWSQuery || service.Protocol == awscatalog.EC2Query {
		return encodeQueryResponse(service, operation, output)
	}
	if service.Protocol != awscatalog.AWSJSON10 && service.Protocol != awscatalog.AWSJSON11 && service.Protocol != awscatalog.RestJSON && service.Protocol != awscatalog.RestXML {
		return nil, fmt.Errorf("%w: %s response", ErrUnsupportedProtocol, service.Protocol)
	}
	if output == nil {
		return nil, fmt.Errorf("nil output for %s", operation.Name)
	}
	if service.Protocol == awscatalog.RestJSON || service.Protocol == awscatalog.RestXML {
		response, err := EncodeHTTPResponse(service, operation, output)
		if err == nil && response.Stream != nil {
			return nil, fmt.Errorf("%w: event streams require EncodeHTTPResponse", ErrUnsupportedBinding)
		}
		return response.Body, err
	}
	return encodeValue(service, operation.Output, reflect.ValueOf(output), "", documentPosition{response: true})
}

// EncodeDocument serializes a generated value outside its wire protocol. A
// projection selects native audit names and public fields without first encoding
// omitted payloads. A nil projection retains the modeled document unchanged.
func EncodeDocument(service awscatalog.Service, shape awscatalog.ShapeID, value any, projection *DocumentProjection) ([]byte, error) {
	body, err := encodeValue(service, shape, reflect.ValueOf(value), "", documentPosition{projection: projection})
	if err == nil && projection != nil && (body == nil || string(body) == "{}") {
		return []byte("null"), nil
	}
	return body, err
}

func encodeValue(service awscatalog.Service, id awscatalog.ShapeID, value reflect.Value, timestampFormat string, position documentPosition) (json.RawMessage, error) {
	shape, ok := service.Shape(id)
	if !ok {
		return nil, fmt.Errorf("missing generated shape %s", id)
	}
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return json.RawMessage("null"), nil
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return json.RawMessage("null"), nil
	}
	if replacement, handled := position.replacement(shape, value); handled {
		return replacement, nil
	}
	if shape.Streaming && shape.Kind == "union" {
		return nil, fmt.Errorf("%w: event stream %s requires HTTP streaming", ErrUnsupportedBinding, id)
	}
	switch shape.Kind {
	case "structure", "union":
		return encodeStructure(service, shape, value, position)
	case "list", "set":
		if value.Kind() != reflect.Slice {
			return nil, outputTypeError(id, value)
		}
		position.sensitive = shape.Member.Sensitive
		items := make([]json.RawMessage, 0, value.Len())
		for i := range value.Len() {
			item, err := encodeValue(service, shape.Member.Target, value.Index(i), shape.Member.TimestampFormat, position)
			if err != nil {
				return nil, err
			}
			if item == nil {
				continue
			}
			if string(item) == "null" && !shape.Sparse {
				return nil, fmt.Errorf("null member in nonsparse output %s", id)
			}
			items = append(items, item)
		}
		return json.Marshal(items)
	case "map":
		if value.Kind() != reflect.Map || value.Type().Key().Kind() != reflect.String {
			return nil, outputTypeError(id, value)
		}
		position.sensitive = shape.Value.Sensitive
		items := make(map[string]json.RawMessage, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			item, err := encodeValue(service, shape.Value.Target, iterator.Value(), shape.Value.TimestampFormat, position)
			if err != nil {
				return nil, err
			}
			if item == nil {
				continue
			}
			if string(item) == "null" && !shape.Sparse {
				return nil, fmt.Errorf("null member in nonsparse output %s", id)
			}
			items[iterator.Key().String()] = item
		}
		return json.Marshal(items)
	case "timestamp":
		stamp, ok := value.Interface().(time.Time)
		if !ok {
			return nil, outputTypeError(id, value)
		}
		if position.rule.TimeLayout != "" {
			return json.Marshal(stamp.UTC().Format(position.rule.TimeLayout))
		}
		if position.sdkOptimized {
			return json.RawMessage(strconv.FormatInt(stamp.UnixMilli(), 10)), nil
		}
		if position.sdk {
			timestampFormat = "date-time"
		}
		if timestampFormat == "" {
			timestampFormat = shape.TimestampFormat
		}
		switch timestampFormat {
		case "date-time":
			return json.Marshal(stamp.UTC().Format(time.RFC3339Nano))
		case "", "epoch-seconds":
		default:
			return nil, fmt.Errorf("unsupported timestamp format %q for %s", timestampFormat, id)
		}
		// Keep nanosecond precision instead of losing it through float64.
		seconds, nanos := stamp.Unix(), int64(stamp.Nanosecond())
		if seconds < 0 && nanos > 0 {
			seconds++
			nanos = 1_000_000_000 - nanos
			if seconds == 0 {
				return json.RawMessage("-0." + strings.TrimRight(fmt.Sprintf("%09d", nanos), "0")), nil
			}
		}
		text := strconv.FormatInt(seconds, 10)
		if nanos > 0 {
			text += "." + strings.TrimRight(fmt.Sprintf("%09d", nanos), "0")
		}
		return json.RawMessage(text), nil
	case "blob":
		if value.Kind() != reflect.Slice || value.Type().Elem().Kind() != reflect.Uint8 {
			return nil, outputTypeError(id, value)
		}
		if position.sdk {
			return json.Marshal(string(value.Bytes()))
		}
		return json.Marshal(base64.StdEncoding.EncodeToString(value.Bytes()))
	case "string", "enum":
		if value.Kind() != reflect.String {
			return nil, outputTypeError(id, value)
		}
		return json.Marshal(value.String())
	case "boolean":
		if value.Kind() != reflect.Bool {
			return nil, outputTypeError(id, value)
		}
		return json.Marshal(value.Bool())
	case "byte", "short", "integer", "long", "intEnum":
		if !value.CanInt() {
			return nil, outputTypeError(id, value)
		}
		return json.RawMessage(strconv.FormatInt(value.Int(), 10)), nil
	case "float", "double":
		if !value.CanFloat() {
			return nil, outputTypeError(id, value)
		}
		number := value.Float()
		switch {
		case math.IsNaN(number):
			return json.RawMessage(`"NaN"`), nil
		case math.IsInf(number, 1):
			return json.RawMessage(`"Infinity"`), nil
		case math.IsInf(number, -1):
			return json.RawMessage(`"-Infinity"`), nil
		default:
			return json.Marshal(number)
		}
	case "document":
		return json.Marshal(value.Interface())
	default:
		return nil, fmt.Errorf("unsupported response shape kind %s", shape.Kind)
	}
}

// encodeJSONMember is the shared presence rule for root HTTP documents and nested
// structures. Only reviewed response members retain nil as null; present empty
// collections remain empty.
func encodeJSONMember(service awscatalog.Service, member awscatalog.Member, field reflect.Value, position documentPosition) (json.RawMessage, error) {
	if nilValue(field) {
		if position.sdkOptimized {
			shape, _ := service.Shape(member.Target)
			if shape.Kind == "list" || shape.Kind == "set" {
				return json.RawMessage("[]"), nil
			}
		}
		if position.sdk && position.sdkInvokePayload {
			// Native SDK Invoke retains an empty response payload as text.
			return encodeValue(service, member.Target, field, member.TimestampFormat, position)
		}
		if position.response && member.JSONResponseNull {
			return json.RawMessage("null"), nil
		}
		return nil, nil
	}
	return encodeValue(service, member.Target, field, member.TimestampFormat, position)
}

func encodeStructure(service awscatalog.Service, shape awscatalog.Shape, value reflect.Value, position documentPosition) (json.RawMessage, error) {
	fields, err := smithyFields(value, shape.ID)
	if err != nil {
		return nil, err
	}
	object := make(map[string]json.RawMessage, len(shape.Members))
	selected := 0
	for _, member := range shape.Members {
		field, ok := fields[member.Name]
		if !ok {
			return nil, fmt.Errorf("output %s missing generated member %s", shape.ID, member.Name)
		}
		if shape.Kind == "union" && !nilValue(field) {
			selected++
		}
		memberPosition := position.member(member)
		encoded, err := encodeJSONMember(service, member, field, memberPosition)
		if err != nil {
			return nil, err
		}
		if encoded == nil {
			continue
		}
		if position.sdk && sdkHTTPDateString(member.Target) {
			// The SDK exposes both the parsed timestamp and original header.
			object[memberPosition.name(member)+"String"] = encoded
			encoded, err = sdkEncodeHTTPDate(encoded)
			if err != nil {
				return nil, err
			}
		}
		object[memberPosition.name(member)] = encoded
	}
	if shape.Kind == "union" && position.projection == nil && selected != 1 {
		return nil, fmt.Errorf("output union %s must have one member", shape.ID)
	}
	return json.Marshal(object)
}

func nilValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Chan:
		return value.IsNil()
	default:
		return false
	}
}

func outputTypeError(id awscatalog.ShapeID, value reflect.Value) error {
	return fmt.Errorf("output type %s does not match generated shape %s", value.Type(), id)
}
