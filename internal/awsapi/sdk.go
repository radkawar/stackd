package awsapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"stackd/internal/awscatalog"
	"stackd/internal/awschecksum"
)

// PrepareSDKChecksums applies SDK request middleware to the final generated DTO.
// It runs after service-owned callers install their actual binary body.
func PrepareSDKChecksums(service awscatalog.Service, operation awscatalog.Operation, input any) error {
	shape, _ := service.Shape(operation.Input)
	var payload, algorithmMember string
	for _, member := range shape.Members {
		if member.HTTPPayload {
			target, _ := service.Shape(member.Target)
			if target.Kind == "blob" && target.Streaming {
				payload = member.Name
			}
		}
		if strings.EqualFold(member.HTTPHeader, "x-amz-sdk-checksum-algorithm") {
			algorithmMember = member.Name
		}
	}
	if payload == "" || algorithmMember == "" {
		return nil
	}
	fields, err := smithyFields(reflect.ValueOf(input), shape.ID)
	if err != nil {
		return err
	}
	setString := func(field reflect.Value, text string) {
		value := reflect.New(field.Type().Elem())
		value.Elem().SetString(text)
		field.Set(value)
	}
	algorithm := "CRC32"
	if field := fields[algorithmMember]; !field.IsNil() {
		algorithm = field.Elem().String()
	} else {
		// A supplied checksum suppresses the default algorithm. An explicit
		// algorithm still requests its own checksum, even if another is set.
		for _, member := range shape.Members {
			if strings.HasPrefix(strings.ToLower(member.HTTPHeader), "x-amz-checksum-") {
				target, _ := service.Shape(member.Target)
				if target.Kind == "string" && !fields[member.Name].IsNil() {
					return nil
				}
			}
		}
		setString(field, algorithm)
	}
	header := "x-amz-checksum-" + strings.ToLower(algorithm)
	for _, member := range shape.Members {
		if !strings.EqualFold(member.HTTPHeader, header) {
			continue
		}
		field := fields[member.Name]
		if !field.IsNil() {
			return nil
		}
		checksum, err := awschecksum.Sum(algorithm, fields[payload].Bytes())
		if err != nil {
			return err
		}
		setString(field, checksum)
		return nil
	}
	return fmt.Errorf("%w: SDK checksum %s", ErrUnsupportedBinding, algorithm)
}

// DecodeSDKInput binds a Step Functions AWS SDK document to a generated input.
// SDK member names are case-insensitive Smithy names, not HTTP, Query or XML
// bindings. The ordinary Smithy decoder owns presence and modeled validation.
func DecodeSDKInput(service awscatalog.Service, operation awscatalog.Operation, payload []byte, input any) error {
	value := reflect.ValueOf(input)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return errors.New("AWS SDK destination must be a nonnil pointer")
	}
	normalized, err := normalizeValue(service, operation.Input, payload, "", awscatalog.Constraints{}, "", documentInput{sdk: true, validate: true, sdkInvokePayload: service.Name == "lambda" && operation.Name == "Invoke"})
	if err != nil {
		return err
	}
	if err := json.Unmarshal(normalized, input); err != nil {
		return fmt.Errorf("bind generated %s SDK input: %w", operation.Name, err)
	}
	return nil
}

// EncodeSDKOutput projects generated output as an SDK document. It deliberately
// excludes transport metadata and optimized-integration envelopes. Timestamps
// are ISO 8601 strings. Blobs are UTF-8 text, not the service wire's base64.
func EncodeSDKOutput(service awscatalog.Service, operation awscatalog.Operation, output any) ([]byte, error) {
	if output == nil {
		return nil, fmt.Errorf("nil output for %s", operation.Name)
	}
	return encodeValue(service, operation.Output, reflect.ValueOf(output), "", documentPosition{sdk: true, sdkInvokePayload: service.Name == "lambda" && operation.Name == "Invoke"})
}

// EncodeOptimizedSDKDocument uses generated shape authority for the Java object
// projection of optimized integrations: millisecond dates and initialized list
// getters, without transport metadata. Ordinary AWS SDK tasks retain their
// separate ISO-8601 output contract.
func EncodeOptimizedSDKDocument(service awscatalog.Service, shape awscatalog.ShapeID, output any) ([]byte, error) {
	if output == nil {
		return nil, fmt.Errorf("nil output for %s", shape)
	}
	return encodeValue(service, shape, reflect.ValueOf(output), "", documentPosition{sdk: true, sdkOptimized: true})
}

// ValidateSDKTemplate checks static SDK method parameters. Only the method's
// required parameters are admission requirements; nested required members are
// validated by the destination service. Streaming inputs are separate required
// Java SDK method arguments even where Smithy permits an omitted HTTP body.
func ValidateSDKTemplate(service awscatalog.Service, id awscatalog.ShapeID, value any, jsonPath bool) []error {
	object, known := value.(map[string]any)
	if !known {
		return nil // An omitted template or JSONata expression is runtime input.
	}
	shape, _ := service.Shape(id)
	var diagnostics []error
	missing := func(member awscatalog.Member) {
		name := sdkMemberName(member.Name)
		_, present := object[name]
		_, dynamic := object[name+".$"]
		if !present && !(jsonPath && dynamic) {
			diagnostics = append(diagnostics, fmt.Errorf("the field %q is required but was missing", name))
		}
	}
	for _, member := range shape.Members {
		if member.Required {
			missing(member)
		}
	}
	for _, member := range shape.Members {
		target, _ := service.Shape(member.Target)
		if member.HTTPPayload && target.Streaming && target.Kind == "blob" && !member.Required {
			missing(member)
		}
	}
	if len(diagnostics) != 0 {
		return diagnostics
	}
	if err := validateSDKTemplateValue(service, id, value, jsonPath); err != nil {
		return []error{err}
	}
	return nil
}

func validateSDKTemplateValue(service awscatalog.Service, id awscatalog.ShapeID, value any, jsonPath bool) error {
	if value == nil {
		return nil
	}
	if text, ok := value.(string); ok && !jsonPath && strings.HasPrefix(text, "{%") && strings.HasSuffix(text, "%}") {
		return nil
	}
	shape, _ := service.Shape(id)
	switch shape.Kind {
	case "structure", "union":
		object, known := value.(map[string]any)
		if !known {
			return errors.New("expected an SDK structure")
		}
		for _, key := range slices.Sorted(maps.Keys(object)) {
			name := key
			dynamic := jsonPath && strings.HasSuffix(name, ".$")
			if dynamic {
				name = strings.TrimSuffix(name, ".$")
			}
			var target awscatalog.ShapeID
			for _, member := range shape.Members {
				if sdkMemberName(member.Name) == name {
					target = member.Target
					break
				}
			}
			if target == "" {
				return fmt.Errorf("the field %q is not supported", name)
			}
			if !dynamic {
				if err := validateSDKTemplateValue(service, target, object[key], jsonPath); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			}
		}
	case "list":
		items, known := value.([]any)
		if !known {
			return errors.New("expected an SDK list")
		}
		for _, item := range items {
			if err := validateSDKTemplateValue(service, shape.Member.Target, item, jsonPath); err != nil {
				return err
			}
		}
	case "map":
		entries, known := value.(map[string]any)
		if !known {
			return errors.New("expected an SDK map")
		}
		for _, name := range slices.Sorted(maps.Keys(entries)) {
			if jsonPath && strings.HasSuffix(name, ".$") {
				continue
			}
			if err := validateSDKTemplateValue(service, shape.Value.Target, entries[name], jsonPath); err != nil {
				return err
			}
		}
	case "boolean":
		_, err := sdkBoolean(value)
		return err
	case "string", "enum":
		if _, known := value.(string); !known {
			return errors.New("expected an SDK string")
		}
	case "byte", "short", "integer", "long", "intEnum":
		number, known := value.(json.Number)
		if !known || strings.ContainsAny(string(number), ".eE") {
			return errors.New("expected an SDK integer")
		}
	}
	return nil
}

// sdkBoolean owns the Java SDK's scalar coercion for both template admission
// and execution. This does not relax the public AWS JSON protocol decoder.
func sdkBoolean(value any) (any, error) {
	switch value := value.(type) {
	case nil, bool:
		return value, nil
	case string:
		switch strings.TrimFunc(value, func(r rune) bool { return r <= 0x20 }) {
		case "true", "True", "TRUE":
			return true, nil
		case "false", "False", "FALSE":
			return false, nil
		case "", "null":
			return nil, nil
		}
	case json.Number:
		if !strings.ContainsAny(string(value), ".eE") {
			return value != "0" && value != "-0", nil
		}
	}
	return nil, errors.New("expected an SDK boolean")
}

// sdkMemberName follows the Java SDK's bean-member convention: normalize only
// the leading acronym, not interior acronyms (MD5OfBody -> Md5OfBody, ETag ->
// ETag, ChecksumCRC32 -> ChecksumCRC32). EqualsValue is documented by Step
// Functions because equals is a reserved Java method name.
func sdkMemberName(name string) string {
	if name == "" {
		return name
	}
	if strings.EqualFold(name, "equals") {
		return "EqualsValue"
	}
	end := 1
	for end < len(name) && name[end] >= 'A' && name[end] <= 'Z' {
		if end+1 < len(name) && name[end+1] >= 'a' && name[end+1] <= 'z' {
			break
		}
		end++
	}
	if end == 1 && name[0] >= 'A' && name[0] <= 'Z' {
		return name
	}
	return strings.ToUpper(name[:1]) + strings.ToLower(name[1:end]) + name[end:]
}

func sdkInputMember(object map[string]json.RawMessage, member awscatalog.Member, path string) (json.RawMessage, error) {
	name := sdkMemberName(member.Name)
	var selected json.RawMessage
	for key, value := range object {
		if !strings.EqualFold(key, member.Name) && !strings.EqualFold(key, name) {
			continue
		}
		if selected != nil {
			return nil, &ValidationError{Path: path, Reason: "SDK member occurs more than once"}
		}
		selected = value
	}
	return selected, nil
}

// A streaming SDK input is a JSON document, including a string's quotes and
// escapes or the literal null. Nonstream blobs instead take the string's UTF-8
// bytes. Decode with UseNumber to preserve integer precision.
func sdkStreamDocument(raw json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil || !json.Valid(raw) {
		return nil, &ValidationError{Reason: "expected a JSON stream document"}
	}
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	// The ordinary generated []byte binder consumes base64 JSON strings.
	return json.Marshal(payload.Bytes()[:payload.Len()-1])
}

// Lambda Invoke's nonstream payload accepts JSON documents or verbatim text.
// In particular a base64-looking string is not decoded, and a JSON-text string
// is not serialized a second time. Null and omission leave the payload absent;
// the service owns its empty-body default, unlike explicit text "null".
func sdkInvokeDocument(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return json.Marshal([]byte(text))
	}
	return sdkStreamDocument(raw)
}

// The Java SDK used by Step Functions retains a timestamp view of Expires,
// while the current Smithy wire contract permits an opaque HTTP header string.
// Keep this SDK compatibility at the shape boundary for every operation using
// the shape; changing the service's DTO would also change its public wire API.
func sdkHTTPDateString(id awscatalog.ShapeID) bool {
	return id == "com.amazonaws.s3#Expires"
}

func sdkDecodeHTTPDate(raw json.RawMessage, path string) (json.RawMessage, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, &ValidationError{Path: path, Reason: "expected a formatted timestamp string", TypeMismatch: true}
	}
	stamp, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return nil, &ValidationError{Path: path, Reason: "invalid formatted timestamp"}
	}
	return json.Marshal(stamp.UTC().Format(http.TimeFormat))
}

func sdkEncodeHTTPDate(raw json.RawMessage) (json.RawMessage, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return nil, err
	}
	stamp, err := http.ParseTime(text)
	if err != nil {
		return nil, err
	}
	return json.Marshal(stamp.UTC().Format(time.RFC3339Nano))
}
