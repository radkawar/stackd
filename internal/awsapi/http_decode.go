package awsapi

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awscatalog"
)

// checkHTTPShape permits supported output event streams and buffered blob payloads.
// Streaming inputs remain unsupported; streaming blobs are represented by []byte.
func checkHTTPShape(service awscatalog.Service, id awscatalog.ShapeID, output bool) (awscatalog.Shape, error) {
	shape, ok := service.Shape(id)
	if !ok {
		return shape, fmt.Errorf("missing generated shape %s", id)
	}
	if shape.Kind != "structure" {
		return shape, fmt.Errorf("%w: HTTP root %s", ErrUnsupportedBinding, id)
	}
	for _, member := range shape.Members {
		target, _ := service.Shape(member.Target)
		if output && !member.HostLabel && member.HTTPPayload && target.Streaming && target.Kind == "union" {
			if err := checkEventStream(service, target); err != nil {
				return shape, err
			}
			continue
		}
		// A header-bound input host label has an ordinary HTTP binding. Host
		// extraction belongs to endpoint routing; unbound labels remain unsupported.
		if (member.HostLabel && (output || member.HTTPHeader == "")) || (target.Streaming && (target.Kind != "blob" || !member.HTTPPayload)) {
			return shape, fmt.Errorf("%w: %s.%s", ErrUnsupportedBinding, id, member.Name)
		}
	}
	return shape, nil
}

func smithyFields(value reflect.Value, id awscatalog.ShapeID) (map[string]reflect.Value, error) {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return nil, fmt.Errorf("nil value for %s", id)
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected generated structure %s", id)
	}
	fields := make(map[string]reflect.Value, value.NumField())
	for i := range value.NumField() {
		if name := value.Type().Field(i).Tag.Get("smithy"); name != "" {
			fields[name] = value.Field(i)
		}
	}
	return fields, nil
}

func memberJSONName(member awscatalog.Member) string {
	if member.JSONName != "" {
		return member.JSONName
	}
	return member.Name
}

func documentMember(member awscatalog.Member, output bool) bool {
	if member.HTTPHeader != "" || member.HTTPPayload || member.HTTPPrefixHeadersSet {
		return false
	}
	// Smithy query and label traits bind requests only. Published models also
	// carry them on response members, including API Gateway pagination tokens.
	if output {
		return !member.HTTPResponseCode
	}
	return !member.HTTPLabel && !member.HostLabel && member.HTTPQuery == "" && !member.HTTPQueryParams
}

func decodeHTTPInput(service awscatalog.Service, operation awscatalog.Operation, request Request, out any, validate bool) error {
	shape, err := checkHTTPShape(service, operation.Input, false)
	if err != nil {
		return err
	}
	if _, err := checkHTTPShape(service, operation.Output, true); err != nil {
		return err
	}
	fields, err := smithyFields(reflect.ValueOf(out), shape.ID)
	if err != nil {
		return err
	}
	payload := false
	for _, member := range shape.Members {
		payload = payload || member.HTTPPayload
	}
	var document map[string]json.RawMessage
	if !payload && len(bytes.TrimSpace(request.Body)) > 0 {
		if service.Protocol == awscatalog.RestXML {
			document, err = decodeXMLDocument(service, shape, request.Body)
			if err != nil {
				return err
			}
		} else if err := json.Unmarshal(request.Body, &document); err != nil || document == nil {
			return &ValidationError{Reason: "expected an object"}
		}
	}
	for _, member := range shape.Members {
		field, ok := fields[member.Name]
		if !ok || !field.CanAddr() {
			return fmt.Errorf("input %s missing generated member %s", shape.ID, member.Name)
		}
		var raw json.RawMessage
		switch {
		case member.HTTPLabel:
			if text, present := request.Labels[member.Name]; present {
				raw, err = decodeHTTPValues(service, member, []string{text}, false)
			}
		case member.HTTPQuery != "":
			raw, err = decodeHTTPValues(service, member, request.Query[member.HTTPQuery], false)
		case member.HTTPHeader != "":
			raw, err = decodeHTTPValues(service, member, request.Header.Values(member.HTTPHeader), true)
		case member.HTTPPrefixHeadersSet:
			values := make(map[string][]string)
			for name, items := range request.Header {
				if len(name) >= len(member.HTTPPrefixHeaders) && strings.EqualFold(name[:len(member.HTTPPrefixHeaders)], member.HTTPPrefixHeaders) {
					values[strings.ToLower(name[len(member.HTTPPrefixHeaders):])] = items
				}
			}
			raw, err = decodeHTTPMap(service, member, values, true)
		case member.HTTPQueryParams:
			values := make(map[string][]string)
			for name, items := range request.Query {
				values[name] = items
			}
			for _, bound := range shape.Members {
				if bound.HTTPQuery != "" {
					delete(values, bound.HTTPQuery)
				}
			}
			raw, err = decodeHTTPMap(service, member, values, false)
		case member.HTTPPayload:
			target, _ := service.Shape(member.Target)
			switch target.Kind {
			case "blob":
				if field.Kind() != reflect.Slice || field.Type().Elem().Kind() != reflect.Uint8 {
					return fmt.Errorf("input payload %s is not a blob", member.Name)
				}
				if validate {
					constraints := mergeConstraints(target.Constraints, member.Constraints)
					if err := checkBounds(constraints.Length, strconv.Itoa(len(request.Body)), member.Name, "length"); err != nil {
						return err
					}
				}
				// Raw payloads are binary-safe and borrow the bounded request body;
				// never base64 encode, JSON marshal, or copy them to bind the DTO.
				field.SetBytes(request.Body)
				continue
			case "string", "enum":
				raw, err = json.Marshal(string(request.Body))
			default:
				if service.Protocol == awscatalog.RestXML {
					raw, err = decodeXMLPayload(service, member, request.Body)
				} else {
					raw = request.Body
				}
			}
		case documentMember(member, false):
			raw = document[memberJSONName(member)]
		default:
			return fmt.Errorf("%w: input %s.%s", ErrUnsupportedBinding, shape.ID, member.Name)
		}
		var normalized json.RawMessage
		if err == nil {
			wireJSON := service.Protocol == awscatalog.RestJSON && (documentMember(member, false) || member.HTTPPayload)
			normalized, err = normalizeMember(service, member, raw, member.Name, documentInput{wireJSON: wireJSON, validate: validate})
		}
		if err != nil {
			var validation *ValidationError
			if errors.As(err, &validation) {
				if member.HTTPQuery != "" {
					validation.HTTPValue = request.Query.Get(member.HTTPQuery)
				} else if member.HTTPHeader != "" {
					validation.HTTPValue = request.Header.Get(member.HTTPHeader)
				}
			}
			return err
		}
		if normalized == nil {
			continue
		}
		if err := json.Unmarshal(normalized, field.Addr().Interface()); err != nil {
			return fmt.Errorf("bind generated %s.%s: %w", operation.Name, member.Name, err)
		}
	}
	return nil
}

func decodeHTTPValues(service awscatalog.Service, member awscatalog.Member, values []string, header bool) (json.RawMessage, error) {
	if len(values) == 0 {
		return nil, nil
	}
	shape, ok := service.Shape(member.Target)
	if !ok {
		return nil, fmt.Errorf("missing generated shape %s", member.Target)
	}
	if shape.Kind == "list" || shape.Kind == "set" {
		if header {
			element, _ := service.Shape(shape.Member.Target)
			if element.Kind == "timestamp" {
				return nil, fmt.Errorf("%w: timestamp header list", ErrUnsupportedBinding)
			}
			reader := csv.NewReader(strings.NewReader(strings.Join(values, ",")))
			reader.TrimLeadingSpace = true
			var err error
			values, err = reader.Read()
			if err != nil {
				return nil, &ValidationError{Path: member.Name, Reason: "invalid header list"}
			}
		}
		items := make([]json.RawMessage, len(values))
		for i, text := range values {
			var err error
			element := shape.Member
			if member.TimestampFormat != "" {
				element.TimestampFormat = member.TimestampFormat
			}
			items[i], err = decodeHTTPValues(service, element, []string{text}, header)
			if err != nil {
				return nil, err
			}
		}
		return json.Marshal(items)
	}
	// Smithy servers take the first occurrence for non-list query members.
	text := values[0]
	if header {
		text = strings.TrimSpace(text)
	}
	invalid := func(reason string) (json.RawMessage, error) {
		return nil, &ValidationError{Path: member.Name, Reason: reason}
	}
	switch shape.Kind {
	case "string", "enum":
		if header && shape.MediaType != "" {
			decoded, err := base64.StdEncoding.DecodeString(text)
			if err != nil {
				return invalid("expected base64-encoded header")
			}
			text = string(decoded)
		}
		return json.Marshal(text)
	case "boolean":
		if text != "true" && text != "false" {
			return invalid("expected a boolean")
		}
		return json.RawMessage(text), nil
	case "byte", "short", "integer", "long", "float", "double", "intEnum":
		if !httpNumber(text) {
			return invalid("expected a number")
		}
		return json.RawMessage(text), nil
	case "timestamp":
		format := member.TimestampFormat
		if format == "" {
			format = shape.TimestampFormat
		}
		if format == "" {
			format = "date-time"
			if header {
				format = "http-date"
			}
		}
		switch format {
		case "epoch-seconds":
			if !httpNumber(text) {
				return invalid("expected timestamp seconds")
			}
			return json.RawMessage(text), nil
		case "date-time":
			stamp, err := time.Parse(time.RFC3339Nano, text)
			if err != nil {
				return invalid("expected an ISO 8601 timestamp")
			}
			return json.Marshal(stamp)
		case "http-date":
			stamp, err := http.ParseTime(text)
			if err != nil {
				return invalid("expected an HTTP date")
			}
			return json.Marshal(stamp)
		}
	}
	return nil, fmt.Errorf("%w: %s HTTP scalar", ErrUnsupportedBinding, member.Target)
}

func httpNumber(text string) bool {
	return len(text) > 0 && (text[0] == '-' || (text[0] >= '0' && text[0] <= '9')) && json.Valid([]byte(text))
}

func decodeHTTPMap(service awscatalog.Service, member awscatalog.Member, values map[string][]string, header bool) (json.RawMessage, error) {
	if len(values) == 0 {
		return nil, nil
	}
	shape, ok := service.Shape(member.Target)
	if !ok || shape.Kind != "map" {
		return nil, fmt.Errorf("%w: %s HTTP map", ErrUnsupportedBinding, member.Target)
	}
	result := make(map[string]json.RawMessage, len(values))
	for name, items := range values {
		raw, err := decodeHTTPValues(service, shape.Value, items, header)
		if err != nil {
			return nil, err
		}
		result[name] = raw
	}
	return json.Marshal(result)
}
