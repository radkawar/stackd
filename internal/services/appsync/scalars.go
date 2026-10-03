package appsync

import (
	"encoding/json"
	"fmt"
	"math"
	"net/mail"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
)

func coerceInput(schema *ast.Schema, typ *ast.Type, input any) (any, error) {
	if input == nil {
		if typ.NonNull {
			return nil, fmt.Errorf("%s cannot be null", typ.String())
		}
		return nil, nil
	}
	if typ.Elem != nil {
		rv := reflect.ValueOf(input)
		if rv.Kind() != reflect.Slice {
			value, err := coerceInput(schema, typ.Elem, input)
			return []any{value}, err
		}
		list := make([]any, rv.Len())
		for i := range rv.Len() {
			var err error
			list[i], err = coerceInput(schema, typ.Elem, rv.Index(i).Interface())
			if err != nil {
				return nil, err
			}
		}
		return list, nil
	}
	def := schema.Types[typ.NamedType]
	if def == nil {
		return nil, fmt.Errorf("unknown input type %s", typ.NamedType)
	}
	if def.Kind == ast.InputObject {
		object, ok := input.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected input object %s", def.Name)
		}
		out := make(map[string]any, len(object))
		for key, value := range object {
			field := def.Fields.ForName(key)
			if field == nil {
				return nil, fmt.Errorf("unknown input field %s.%s", def.Name, key)
			}
			coerced, err := coerceInput(schema, field.Type, value)
			if err != nil {
				return nil, err
			}
			out[key] = coerced
		}
		for _, field := range def.Fields {
			if _, ok := out[field.Name]; !ok {
				if field.DefaultValue != nil {
					v, err := field.DefaultValue.Value(nil)
					if err != nil {
						return nil, err
					}
					out[field.Name], err = coerceInput(schema, field.Type, v)
					if err != nil {
						return nil, err
					}
				} else if field.Type.NonNull {
					return nil, fmt.Errorf("required input field %s.%s is missing", def.Name, field.Name)
				}
			}
		}
		return out, nil
	}
	if def.Kind == ast.Enum {
		str, ok := input.(string)
		if !ok || def.EnumValues.ForName(str) == nil {
			return nil, fmt.Errorf("invalid %s enum value", def.Name)
		}
		return str, nil
	}
	if strings.HasPrefix(def.Name, "AWS") {
		return awsScalar(def.Name, input, true)
	}
	if def.Name == "Int" {
		n, ok := number(input)
		if !ok || n != math.Trunc(n) || n < math.MinInt32 || n > math.MaxInt32 {
			return nil, fmt.Errorf("invalid Int value")
		}
		return int64(n), nil
	}
	if def.Name == "ID" {
		if n, ok := number(input); ok && n == math.Trunc(n) {
			return strconv.FormatFloat(n, 'f', 0, 64), nil
		}
	}
	return input, nil
}

func serializeScalar(def *ast.Definition, input any) (any, error) {
	if def.Kind == ast.Enum {
		v, ok := input.(string)
		if !ok || def.EnumValues.ForName(v) == nil {
			return nil, fmt.Errorf("invalid result for enum %s", def.Name)
		}
		return v, nil
	}
	switch def.Name {
	case "String", "ID":
		if v, ok := input.(string); ok {
			return v, nil
		}
		if v, ok := number(input); ok {
			if def.Name == "ID" && math.Trunc(v) != v {
				break
			}
			return strconv.FormatFloat(v, 'f', -1, 64), nil
		}
		if v, ok := input.(bool); ok && def.Name == "String" {
			return strconv.FormatBool(v), nil
		}
	case "Int":
		n, ok := number(input)
		if ok && n == math.Trunc(n) && n >= math.MinInt32 && n <= math.MaxInt32 {
			return int64(n), nil
		}
	case "Float":
		n, ok := number(input)
		if ok {
			return n, nil
		}
	case "Boolean":
		if v, ok := input.(bool); ok {
			return v, nil
		}
		if n, ok := number(input); ok {
			return n != 0, nil
		}
	default:
		if strings.HasPrefix(def.Name, "AWS") {
			return awsScalar(def.Name, input, false)
		}
	}
	return nil, fmt.Errorf("cannot serialize result as %s", def.Name)
}
func number(input any) (float64, bool) {
	var value float64
	switch v := input.(type) {
	case int:
		value = float64(v)
	case int32:
		value = float64(v)
	case int64:
		value = float64(v)
	case uint64:
		value = float64(v)
	case float64:
		value = v
	case float32:
		value = float64(v)
	case json.Number:
		var err error
		value, err = v.Float64()
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return value, !math.IsNaN(value) && !math.IsInf(value, 0)
}

var phonePattern = regexp.MustCompile(`^\+?[0-9][0-9 ()-]{1,30}[0-9]$`)
var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(Z|[+-]\d{2}:\d{2}(:\d{2})?)?$`)
var timePattern = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}(\.\d*)?(Z|[+-]\d{2}:\d{2}(:\d{2})?)?$`)

func awsScalar(kind string, input any, argument bool) (any, error) {
	invalid := func() (any, error) { return nil, fmt.Errorf("invalid value for %s", kind) }
	if kind == "AWSTimestamp" {
		n, ok := number(input)
		if ok && math.Trunc(n) == n && n >= math.MinInt64 && n < math.MaxInt64 {
			return int64(n), nil
		}
		return invalid()
	}
	if kind == "AWSJSON" {
		if argument {
			str, ok := input.(string)
			if !ok {
				return invalid()
			}
			var parsed any
			if json.Unmarshal([]byte(str), &parsed) != nil {
				return invalid()
			}
			return parsed, nil
		}
		// Resolver results for AWSJSON are JSON values, serialized to the GraphQL
		// scalar's string representation rather than emitted as a GraphQL object.
		data, err := json.Marshal(input)
		if err != nil {
			return invalid()
		}
		return string(data), nil
	}
	text, ok := input.(string)
	if !ok {
		return invalid()
	}
	switch kind {
	case "AWSDate":
		if !datePattern.MatchString(text) {
			return invalid()
		}
		if _, err := time.Parse("2006-01-02", text[:10]); err != nil {
			return invalid()
		}
		if !validOffset(text[10:]) {
			return invalid()
		}
	case "AWSTime":
		if !timePattern.MatchString(text) {
			return invalid()
		}
		plain := text
		zoneIndex := strings.IndexAny(text, "Z+-")
		if zoneIndex >= 0 {
			plain = text[:zoneIndex]
			if !validOffset(text[zoneIndex:]) {
				return invalid()
			}
		}
		if _, err := time.Parse("15:04:05", strings.TrimSuffix(plain, ".")); err != nil {
			return invalid()
		}
	case "AWSDateTime":
		parts := strings.SplitN(text, "T", 2)
		if len(parts) != 2 {
			return invalid()
		}
		if _, err := awsScalar("AWSDate", parts[0], true); err != nil {
			return invalid()
		}
		if _, err := awsScalar("AWSTime", parts[1], true); err != nil {
			return invalid()
		}
	case "AWSEmail":
		address, err := mail.ParseAddress(text)
		if err != nil || address.Address != text {
			return invalid()
		}
	case "AWSURL":
		parsed, err := url.Parse(text)
		if err != nil || parsed.Scheme == "" || strings.Contains(parsed.Path, "//") {
			return invalid()
		}
	case "AWSIPAddress":
		if _, err := netip.ParseAddr(text); err != nil {
			if _, err := netip.ParsePrefix(text); err != nil {
				return invalid()
			}
		}
	case "AWSPhone":
		if !phonePattern.MatchString(text) {
			return invalid()
		}
	default:
		return invalid()
	}
	return text, nil
}
func validOffset(offset string) bool {
	if offset == "" || offset == "Z" {
		return true
	}
	if offset[0] != '+' && offset[0] != '-' {
		return false
	}
	parts := strings.Split(offset[1:], ":")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		max := 59
		if i == 0 {
			max = 23
		}
		if err != nil || n < 0 || n > max {
			return false
		}
	}
	return true
}
