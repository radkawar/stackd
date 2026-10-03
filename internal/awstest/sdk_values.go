package awstest

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// These are SDK constructor bindings, not a second wire schema. JSON cannot
// instantiate the concrete implementations of the SDK's union interfaces.
var sdkUnionMembers = map[reflect.Type]map[string]reflect.Type{
	reflect.TypeFor[dynamodbtypes.AttributeValue](): {
		"S":    reflect.TypeFor[dynamodbtypes.AttributeValueMemberS](),
		"N":    reflect.TypeFor[dynamodbtypes.AttributeValueMemberN](),
		"B":    reflect.TypeFor[dynamodbtypes.AttributeValueMemberB](),
		"BOOL": reflect.TypeFor[dynamodbtypes.AttributeValueMemberBOOL](),
		"NULL": reflect.TypeFor[dynamodbtypes.AttributeValueMemberNULL](),
		"SS":   reflect.TypeFor[dynamodbtypes.AttributeValueMemberSS](),
		"NS":   reflect.TypeFor[dynamodbtypes.AttributeValueMemberNS](),
		"BS":   reflect.TypeFor[dynamodbtypes.AttributeValueMemberBS](),
		"L":    reflect.TypeFor[dynamodbtypes.AttributeValueMemberL](),
		"M":    reflect.TypeFor[dynamodbtypes.AttributeValueMemberM](),
	},
	reflect.TypeFor[s3types.MetricsFilter](): {
		"AccessPointArn": reflect.TypeFor[s3types.MetricsFilterMemberAccessPointArn](),
		"And":            reflect.TypeFor[s3types.MetricsFilterMemberAnd](),
		"Prefix":         reflect.TypeFor[s3types.MetricsFilterMemberPrefix](),
		"Tag":            reflect.TypeFor[s3types.MetricsFilterMemberTag](),
	},
	reflect.TypeFor[s3types.AnalyticsFilter](): {
		"And":    reflect.TypeFor[s3types.AnalyticsFilterMemberAnd](),
		"Prefix": reflect.TypeFor[s3types.AnalyticsFilterMemberPrefix](),
		"Tag":    reflect.TypeFor[s3types.AnalyticsFilterMemberTag](),
	},
}

func containsSDKValue(kind reflect.Type, seen map[reflect.Type]bool, timestamps bool) bool {
	if _, ok := sdkUnionMembers[kind]; ok {
		return true
	}
	if timestamps && kind == reflect.TypeFor[time.Time]() {
		return true
	}
	if seen[kind] {
		return false
	}
	seen[kind] = true
	switch kind.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Array:
		return containsSDKValue(kind.Elem(), seen, timestamps)
	case reflect.Struct:
		for i := range kind.NumField() {
			field := kind.Field(i)
			if field.IsExported() && containsSDKValue(field.Type, seen, timestamps) {
				return true
			}
		}
	}
	return false
}

// DecodeSDK decodes native fixture JSON into SDK values, including modeled union
// envelopes and RFC3339 or epoch-second timestamps. SDK serialization and service
// validation remain authoritative.
func DecodeSDK(raw json.RawMessage, target any) error {
	return decodeSDKValue(reflect.ValueOf(target).Elem(), raw)
}

func decodeSDKValue(target reflect.Value, raw json.RawMessage) error {
	if !containsSDKValue(target.Type(), map[reflect.Type]bool{}, true) {
		return json.Unmarshal(raw, target.Addr().Interface())
	}
	if string(raw) == "null" {
		return nil
	}
	if target.Type() == reflect.TypeFor[time.Time]() && len(raw) > 0 && raw[0] != '"' {
		var epoch float64
		if err := json.Unmarshal(raw, &epoch); err != nil {
			return err
		}
		seconds, fraction := math.Modf(epoch)
		target.Set(reflect.ValueOf(time.Unix(int64(seconds), int64(fraction*float64(time.Second))).UTC()))
		return nil
	}
	if members, union := sdkUnionMembers[target.Type()]; union {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return err
		}
		if len(envelope) != 1 {
			return fmt.Errorf("native %s must have one member: %s", target.Type(), raw)
		}
		for name, value := range envelope {
			memberType, ok := members[name]
			if !ok {
				return fmt.Errorf("unknown native %s member %q", target.Type(), name)
			}
			member := reflect.New(memberType)
			if err := decodeSDKValue(member.Elem().FieldByName("Value"), value); err != nil {
				return err
			}
			target.Set(member)
		}
		return nil
	}
	if target.CanAddr() && target.Addr().Type().Implements(reflect.TypeFor[json.Unmarshaler]()) {
		return json.Unmarshal(raw, target.Addr().Interface())
	}
	switch target.Kind() {
	case reflect.Pointer:
		target.Set(reflect.New(target.Type().Elem()))
		return decodeSDKValue(target.Elem(), raw)
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		for name, rawValue := range fields {
			field := target.FieldByName(name)
			if !field.IsValid() {
				if member, ok := target.Type().FieldByNameFunc(func(candidate string) bool { return strings.EqualFold(candidate, name) }); ok {
					field = target.FieldByIndex(member.Index)
				}
			}
			if !field.IsValid() || !field.CanSet() {
				continue // Match encoding/json for fields outside the SDK shape.
			}
			if err := decodeSDKValue(field, rawValue); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	case reflect.Map:
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return err
		}
		target.Set(reflect.MakeMapWithSize(target.Type(), len(entries)))
		for key, rawValue := range entries {
			value := reflect.New(target.Type().Elem()).Elem()
			if err := decodeSDKValue(value, rawValue); err != nil {
				return err
			}
			target.SetMapIndex(reflect.ValueOf(key).Convert(target.Type().Key()), value)
		}
	case reflect.Slice:
		if target.Type().Elem().Kind() == reflect.Uint8 {
			return json.Unmarshal(raw, target.Addr().Interface())
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return err
		}
		target.Set(reflect.MakeSlice(target.Type(), len(entries), len(entries)))
		for i, value := range entries {
			if err := decodeSDKValue(target.Index(i), value); err != nil {
				return err
			}
		}
	default:
		return json.Unmarshal(raw, target.Addr().Interface())
	}
	return nil
}

// MarshalSDK retains native union member names rather than the Go wrapper's
// implementation field "Value". Other SDK values keep their normal JSON form.
func MarshalSDK(value any) ([]byte, error) {
	return json.Marshal(sdkJSONValue(reflect.ValueOf(value)))
}

func sdkJSONValue(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}
	if !containsSDKValue(value.Type(), map[reflect.Type]bool{}, false) {
		return value.Interface()
	}
	if value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		if members, union := sdkUnionMembers[value.Type()]; union {
			member := value.Elem().Elem()
			name := strings.TrimPrefix(member.Type().Name(), value.Type().Name()+"Member")
			if members[name] == member.Type() {
				return map[string]any{name: sdkJSONValue(member.FieldByName("Value"))}
			}
			return value.Interface()
		}
		if value.Kind() == reflect.Interface {
			return value.Interface()
		}
		return sdkJSONValue(value.Elem())
	}
	if value.Type().Implements(reflect.TypeFor[json.Marshaler]()) {
		return value.Interface()
	}
	switch value.Kind() {
	case reflect.Struct:
		out := map[string]any{}
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if field.IsExported() {
				out[field.Name] = sdkJSONValue(value.Field(i))
			}
		}
		return out
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 || value.Kind() == reflect.Slice && value.IsNil() {
			return value.Interface()
		}
		out := make([]any, value.Len())
		for i := range out {
			out[i] = sdkJSONValue(value.Index(i))
		}
		return out
	case reflect.Map:
		if value.IsNil() {
			return nil
		}
		out := make(map[string]any, value.Len())
		for entries := value.MapRange(); entries.Next(); {
			out[entries.Key().String()] = sdkJSONValue(entries.Value())
		}
		return out
	default:
		return value.Interface()
	}
}
