package awsapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"stackd/internal/awscatalog"
)

type documentInput struct {
	wireJSON             bool
	validate             bool
	sdk                  bool
	allowMissingRequired bool
	mockResponse         bool
	sdkInvokePayload     bool
}

func normalizeValue(service awscatalog.Service, id awscatalog.ShapeID, raw json.RawMessage, path string, overrides awscatalog.Constraints, timestampFormat string, mode documentInput) (json.RawMessage, error) {
	shape, ok := service.Shape(id)
	if !ok {
		return nil, fmt.Errorf("missing generated shape %s", id)
	}
	var constraints awscatalog.Constraints
	if mode.validate {
		constraints = mergeConstraints(shape.Constraints, overrides)
	}
	invalid := func(reason string) (json.RawMessage, error) { return nil, &ValidationError{Path: path, Reason: reason} }
	if mode.sdk && !mode.mockResponse && shape.Streaming {
		if shape.Kind != "blob" {
			return nil, fmt.Errorf("%w: SDK event stream %s", ErrUnsupportedBinding, id)
		}
		var err error
		raw, err = sdkStreamDocument(raw)
		if err != nil {
			return nil, err
		}
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, &ValidationError{Path: path, Constraint: "nonnull", Reason: "value must not be null"}
	}
	switch shape.Kind {
	case "structure", "union":
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return invalid("expected an object")
		}
		result := map[string]json.RawMessage{}
		sdkStream := false
		for _, member := range shape.Members {
			name := memberJSONName(member)
			value := object[name]
			if mode.sdk {
				var err error
				value, err = sdkInputMember(object, member, joinPath(path, member.Name))
				if err != nil {
					return nil, err
				}
			}
			normalized, err := normalizeMember(service, member, value, joinPath(path, member.Name), mode)
			if err != nil {
				return nil, err
			}
			if normalized == nil {
				continue
			}
			result[name] = normalized
			if mode.sdk && !mode.mockResponse && member.HTTPPayload {
				target, _ := service.Shape(member.Target)
				sdkStream = target.Streaming && target.Kind == "blob"
			}
		}
		if mode.validate && shape.Kind == "union" && len(result) != 1 {
			return invalid("union must contain exactly one member")
		}
		if sdkStream {
			// SDK stream documents use a text entity. Explicit caller media
			// types remain authoritative; ordinary wire defaults differ.
			for _, member := range shape.Members {
				name := memberJSONName(member)
				if result[name] != nil {
					continue
				}
				switch strings.ToLower(member.HTTPHeader) {
				case "content-type":
					result[name] = json.RawMessage(`"text/plain; charset=UTF-8"`)
				}
			}
		}
		return json.Marshal(result)
	case "list", "set":
		var list []json.RawMessage
		if err := json.Unmarshal(raw, &list); err != nil || list == nil {
			return nil, &ValidationError{Path: path, Reason: "expected an array", TypeMismatch: true}
		}
		if err := checkBounds(constraints.Length, strconv.Itoa(len(list)), path, "length"); err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for i, value := range list {
			if shape.Sparse && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				continue
			}
			normalized, err := normalizeValue(service, shape.Member.Target, value, fmt.Sprintf("%s[%d]", path, i), shape.Member.Constraints, shape.Member.TimestampFormat, mode)
			if err != nil {
				return nil, err
			}
			list[i] = normalized
			if mode.validate && (constraints.UniqueItems || shape.Kind == "set") {
				if seen[string(normalized)] {
					return invalid("collection values must be unique")
				}
				seen[string(normalized)] = true
			}
		}
		return json.Marshal(list)
	case "map":
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return invalid("expected an object")
		}
		if err := checkBounds(constraints.Length, strconv.Itoa(len(object)), path, "length"); err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			keyJSON, _ := json.Marshal(key)
			if _, err := normalizeValue(service, shape.Key.Target, keyJSON, path+"[key]", shape.Key.Constraints, shape.Key.TimestampFormat, mode); err != nil {
				return nil, err
			}
			value := object[key]
			if shape.Sparse && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				continue
			}
			normalized, err := normalizeValue(service, shape.Value.Target, value, path+"[value]", shape.Value.Constraints, shape.Value.TimestampFormat, mode)
			if err != nil {
				return nil, err
			}
			object[key] = normalized
		}
		return json.Marshal(object)
	case "string", "enum", "blob":
		if mode.sdk && sdkHTTPDateString(id) {
			return sdkDecodeHTTPDate(raw, path)
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, &ValidationError{Path: path, Reason: "expected a string", TypeMismatch: true}
		}
		length := utf8.RuneCountInString(value)
		if shape.Kind == "blob" && !mode.mockResponse {
			if mode.sdk && !shape.Streaming {
				length = len(value)
				raw, _ = json.Marshal([]byte(value))
			} else {
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return invalid("expected base64-encoded data")
				}
				length = len(decoded)
			}
		}
		if err := checkBounds(constraints.Length, strconv.Itoa(length), path, "length"); err != nil {
			return nil, err
		}
		if constraints.Pattern != "" {
			matches, err := matchPattern(constraints.Pattern, value)
			if err != nil {
				return nil, fmt.Errorf("evaluate %s pattern: %w", id, err)
			}
			if !matches {
				return nil, &ValidationError{Path: path, Reason: "value does not match the modeled pattern", Constraint: "pattern"}
			}
		}
		if mode.validate && shape.Kind == "enum" && !enumContains(shape.Enum, value) {
			return nil, &ValidationError{Path: path, Reason: "value is not a modeled enum member", Constraint: "enum", EnumValue: value}
		}
		if shape.Kind == "blob" {
			return raw, nil
		}
		return json.Marshal(value)
	case "boolean":
		if mode.sdk {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var value any
			if err := decoder.Decode(&value); err != nil {
				return invalid("expected a boolean")
			}
			coerced, err := sdkBoolean(value)
			if err != nil {
				return invalid(err.Error())
			}
			return json.Marshal(coerced)
		}
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return invalid("expected a boolean")
		}
		return json.Marshal(value)
	case "byte", "short", "integer", "long", "float", "double", "intEnum":
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var parsed any
		if err := decoder.Decode(&parsed); err != nil || !json.Valid(raw) {
			return invalid("expected a number")
		}
		number, ok := parsed.(json.Number)
		if !ok {
			return nil, &ValidationError{Path: path, Reason: "expected a number", TypeMismatch: true}
		}
		text := number.String()
		bits := map[awscatalog.ShapeKind]int{"byte": 8, "short": 16, "integer": 32, "long": 64, "intEnum": 32}[shape.Kind]
		if bits != 0 {
			if shape.JSONIntegerCoercion {
				var err error
				text, err = coerceJSONInteger(text, bits)
				if err != nil {
					return invalid("expected a number convertible to the modeled integer type")
				}
			} else if _, err := strconv.ParseInt(text, 10, bits); err != nil {
				failure := &ValidationError{Path: path, Reason: "expected an integer in the modeled type range"}
				if service.Protocol == awscatalog.AWSQuery {
					failure.Constraint = "query"
				}
				return nil, failure
			}
		} else {
			bits = 64
			if shape.Kind == "float" {
				bits = 32
			}
			if _, err := strconv.ParseFloat(text, bits); err != nil {
				return invalid("number is outside the modeled type range")
			}
		}
		if err := checkBounds(constraints.Range, text, path, "range"); err != nil {
			return nil, err
		}
		if mode.validate && shape.Kind == "intEnum" && !enumContains(shape.Enum, text) {
			return invalid("value is not a modeled enum member")
		}
		return json.RawMessage(text), nil
	case "timestamp":
		// Query, XML and HTTP-bound values have already been decoded. JSON
		// document timestamps still need their modeled wire format enforced.
		if mode.sdk {
			timestampFormat = "date-time"
		} else if mode.wireJSON {
			if timestampFormat == "" {
				timestampFormat = shape.TimestampFormat
			}
			if timestampFormat == "" {
				timestampFormat = "epoch-seconds"
			}
		} else {
			timestampFormat = ""
		}
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			if timestampFormat == "epoch-seconds" {
				return nil, &ValidationError{Path: path, Reason: "expected timestamp seconds", TypeMismatch: true}
			}
			var value time.Time
			var err error
			switch timestampFormat {
			case "", "date-time":
				value, err = time.Parse(time.RFC3339Nano, text)
			case "http-date":
				value, err = http.ParseTime(text)
			default:
				return nil, fmt.Errorf("%w: timestamp format %s", ErrUnsupportedBinding, timestampFormat)
			}
			if err != nil {
				return invalid("invalid formatted timestamp")
			}
			return json.Marshal(value)
		}
		if timestampFormat != "" && timestampFormat != "epoch-seconds" {
			return nil, &ValidationError{Path: path, Reason: "expected a formatted timestamp string", TypeMismatch: true}
		}
		var number json.Number
		if err := json.Unmarshal(raw, &number); err != nil {
			return nil, &ValidationError{Path: path, Reason: "expected timestamp seconds", TypeMismatch: true}
		}
		rational, ok := new(big.Rat).SetString(number.String())
		if !ok {
			return invalid("invalid timestamp seconds")
		}
		seconds, remainder := new(big.Int), new(big.Int)
		seconds.QuoRem(rational.Num(), rational.Denom(), remainder)
		if !seconds.IsInt64() {
			return invalid("timestamp is out of range")
		}
		remainder.Mul(remainder, big.NewInt(1_000_000_000))
		remainder.Quo(remainder, rational.Denom())
		return json.Marshal(time.Unix(seconds.Int64(), remainder.Int64()).UTC())
	case "document":
		if !json.Valid(raw) {
			return invalid("expected a JSON document")
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unsupported generated shape kind %s", shape.Kind)
	}
}

// Native annotated inputs truncate decimal fractions before saturating to the
// modeled signed width. This is provider behavior at the wire boundary, not an
// internal overflow recovery rule. Ordinary integer tokens need no big number.
func coerceJSONInteger(text string, bits int) (string, error) {
	if _, err := strconv.ParseInt(text, 10, bits); err == nil {
		return text, nil
	}
	value, _, err := big.ParseFloat(text, 10, uint(len(text))*4, big.ToZero)
	if err != nil {
		return "", err
	}
	number, _ := value.Int64()
	maximum := int64(uint64(1)<<(bits-1) - 1)
	minimum := -maximum - 1
	return strconv.FormatInt(max(minimum, min(number, maximum)), 10), nil
}

func normalizeMember(service awscatalog.Service, member awscatalog.Member, value json.RawMessage, path string, mode documentInput) (json.RawMessage, error) {
	if mode.sdk && !mode.mockResponse {
		target, _ := service.Shape(member.Target)
		if mode.sdkInvokePayload && member.HTTPPayload && target.Kind == "blob" {
			var err error
			value, err = sdkInvokeDocument(value)
			if err != nil {
				return nil, err
			}
			// sdkInvokeDocument has already encoded the payload bytes for
			// the generated blob binder; do not interpret them a second time.
			mode.sdk = false
		}
		if target.Streaming && target.Kind == "blob" {
			if len(value) != 0 {
				return normalizeValue(service, member.Target, value, path, member.Constraints, member.TimestampFormat, mode)
			}
			// Smithy blob defaults describe bytes, not SDK stream documents.
			mode.sdk = false
		}
	}
	if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		defaultValue := member.Default
		if defaultValue == "" {
			target, _ := service.Shape(member.Target)
			defaultValue = target.Default
		}
		if defaultValue != "" && defaultValue != "null" {
			value = json.RawMessage(defaultValue)
		} else if mode.validate && member.Required && !mode.allowMissingRequired {
			return nil, &ValidationError{Path: path, Reason: "required member is missing", Constraint: "required"}
		} else {
			return nil, nil
		}
	}
	return normalizeValue(service, member.Target, value, path, member.Constraints, member.TimestampFormat, mode)
}

func mergeConstraints(base, overrides awscatalog.Constraints) awscatalog.Constraints {
	if overrides.Length.Min.Set || overrides.Length.Max.Set {
		base.Length = overrides.Length
	}
	if overrides.Range.Min.Set || overrides.Range.Max.Set {
		base.Range = overrides.Range
	}
	if overrides.Pattern != "" {
		base.Pattern = overrides.Pattern
	}
	base.UniqueItems = base.UniqueItems || overrides.UniqueItems
	return base
}

func checkBounds(bounds awscatalog.Bounds, text, path, constraint string) error {
	if !bounds.Min.Set && !bounds.Max.Set {
		return nil
	}
	subject := constraint
	if constraint == "range" {
		subject = "value"
	}
	infinity := 0
	switch text {
	case "+Inf":
		infinity = 1
	case "-Inf":
		infinity = -1
	}
	value, ok := new(big.Rat).SetString(text)
	if !ok && infinity == 0 {
		return &ValidationError{Path: path, Reason: "invalid numerical " + subject}
	}
	for _, check := range []struct {
		bound awscatalog.Bound
		min   bool
	}{{bounds.Min, true}, {bounds.Max, false}} {
		if !check.bound.Set {
			continue
		}
		bound, ok := new(big.Rat).SetString(check.bound.Value)
		if !ok {
			return fmt.Errorf("invalid generated bound %q", check.bound.Value)
		}
		comparison := infinity
		if infinity == 0 {
			comparison = value.Cmp(bound)
		}
		if check.min && comparison < 0 {
			return &ValidationError{Path: path, Reason: subject + " is below minimum " + check.bound.Value, Constraint: constraint + ".min"}
		}
		if !check.min && comparison > 0 {
			return &ValidationError{Path: path, Reason: subject + " exceeds maximum " + check.bound.Value, Constraint: constraint + ".max"}
		}
	}
	return nil
}

func enumContains(values []awscatalog.EnumValue, value string) bool {
	for _, item := range values {
		if item.Value == value {
			return true
		}
	}
	return false
}
