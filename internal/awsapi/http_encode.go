package awsapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awscatalog"
)

// HTTPResponse is a fully bound response. Body may contain arbitrary bytes and
// borrows a raw blob output's backing slice; callers must not mutate it until sent.
// Request identifiers and other unmodeled service headers remain the caller's responsibility.
type HTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	// Stream writes and flushes event frames after the caller sends status and headers.
	// It borrows event data until each write completes and never owns the producer.
	Stream func(context.Context, http.ResponseWriter) error
}

// EncodeHTTPResponse binds the root output using generated Smithy traits. Nested
// structures remain protocol documents even if their members carry HTTP traits.
func EncodeHTTPResponse(service awscatalog.Service, operation awscatalog.Operation, output any) (HTTPResponse, error) {
	response := HTTPResponse{StatusCode: http.StatusOK, Header: make(http.Header)}
	if service.Protocol == awscatalog.AWSJSON11 {
		if streamed, ok, err := encodeJSONEventStreamResponse(service, operation, output); ok || err != nil {
			return streamed, err
		}
	}
	if service.Protocol != awscatalog.RestJSON && service.Protocol != awscatalog.RestXML {
		body, err := EncodeResponse(service, operation, output)
		if err != nil {
			return HTTPResponse{}, err
		}
		response.Body = body
		switch service.Protocol {
		case awscatalog.AWSQuery:
			response.Header.Set("Content-Type", "text/xml")
		case awscatalog.AWSJSON10:
			response.Header.Set("Content-Type", "application/x-amz-json-1.0")
		case awscatalog.AWSJSON11:
			response.Header.Set("Content-Type", "application/x-amz-json-1.1")
		case awscatalog.RPCV2CBOR:
			response.Header.Set("Smithy-Protocol", "rpc-v2-cbor")
			if operation.Output != "smithy.api#Unit" {
				response.Header.Set("Content-Type", "application/cbor")
			}
		}
		return response, nil
	}
	shape, err := checkHTTPShape(service, operation.Output, true)
	if err != nil {
		return HTTPResponse{}, err
	}
	fields, err := smithyFields(reflect.ValueOf(output), shape.ID)
	if err != nil {
		return HTTPResponse{}, err
	}
	if operation.HTTPStatus != 0 {
		response.StatusCode = operation.HTTPStatus
	}
	response.Header.Set("Content-Type", "application/json")
	if service.Protocol == awscatalog.RestXML {
		response.Header.Set("Content-Type", "application/xml")
	}
	var document map[string]json.RawMessage
	documentMembers := false
	payload := false
	// Determine the content type before writing explicit modeled headers, which
	// take precedence over the protocol's default content type.
	for _, member := range shape.Members {
		if member.HTTPPayload {
			payload = true
			target, _ := service.Shape(member.Target)
			if target.Streaming && target.Kind == "union" {
				response.Header.Set("Content-Type", "application/vnd.amazon.eventstream")
			} else if target.MediaType != "" {
				response.Header.Set("Content-Type", target.MediaType)
			} else if target.Kind == "blob" {
				response.Header.Set("Content-Type", "application/octet-stream")
			} else if target.Kind == "string" || target.Kind == "enum" {
				response.Header.Set("Content-Type", "text/plain")
			}
		}
	}
	for _, member := range shape.Members {
		field, ok := fields[member.Name]
		if !ok {
			return HTTPResponse{}, fmt.Errorf("output %s missing generated member %s", shape.ID, member.Name)
		}
		if documentMember(member, true) {
			documentMembers = true
		}
		if !(service.Protocol == awscatalog.RestJSON && documentMember(member, true)) && nilValue(field) {
			continue
		}
		switch {
		case member.HTTPResponseCode:
			value := indirectHTTPValue(field)
			if !value.CanInt() {
				return HTTPResponse{}, outputTypeError(member.Target, value)
			}
			status := value.Int()
			if status < 100 || status > 999 {
				return HTTPResponse{}, fmt.Errorf("invalid HTTP response status for %s", member.Name)
			}
			response.StatusCode = int(status)
		case member.HTTPHeader != "":
			values, err := encodeHTTPHeader(service, member, field)
			if err != nil {
				return HTTPResponse{}, err
			}
			response.Header.Del(member.HTTPHeader)
			for _, value := range values {
				if strings.ContainsAny(value, "\r\n\x00") {
					return HTTPResponse{}, fmt.Errorf("invalid HTTP header value for %s", member.Name)
				}
				response.Header.Add(member.HTTPHeader, value)
			}
		case member.HTTPPrefixHeadersSet:
			target, _ := service.Shape(member.Target)
			value := indirectHTTPValue(field)
			if target.Kind != "map" || value.Kind() != reflect.Map || value.Type().Key().Kind() != reflect.String {
				return HTTPResponse{}, outputTypeError(member.Target, value)
			}
			iterator := value.MapRange()
			for iterator.Next() {
				name := member.HTTPPrefixHeaders + iterator.Key().String()
				if !validHTTPHeaderName(name) {
					return HTTPResponse{}, fmt.Errorf("invalid HTTP metadata header name for %s", member.Name)
				}
				values, err := encodeHTTPHeader(service, target.Value, iterator.Value())
				if err != nil {
					return HTTPResponse{}, err
				}
				for _, text := range values {
					if strings.ContainsAny(text, "\r\n\x00") {
						return HTTPResponse{}, fmt.Errorf("invalid HTTP metadata header value for %s", member.Name)
					}
				}
				// Canonical MIME casing changes the metadata map keys some SDKs see.
				response.Header[name] = values
			}
		case member.HTTPPayload:
			target, _ := service.Shape(member.Target)
			value := indirectHTTPValue(field)
			if target.Streaming && target.Kind == "union" {
				if value.Kind() != reflect.Chan || value.Type().ChanDir() == reflect.SendDir || value.Type().Elem().Kind() != reflect.Struct {
					return HTTPResponse{}, outputTypeError(member.Target, value)
				}
				response.Stream = encodeEventStream(service, target, value, nil)
				continue
			}
			switch target.Kind {
			case "blob":
				if value.Kind() != reflect.Slice || value.Type().Elem().Kind() != reflect.Uint8 {
					return HTTPResponse{}, outputTypeError(member.Target, value)
				}
				response.Body = value.Bytes()
			case "string", "enum":
				if value.Kind() != reflect.String {
					return HTTPResponse{}, outputTypeError(member.Target, value)
				}
				response.Body = []byte(value.String())
			default:
				if service.Protocol == awscatalog.RestXML {
					response.Body, err = encodeXMLBody(service, member, field, false)
				} else {
					response.Body, err = encodeValue(service, member.Target, field, member.TimestampFormat, documentPosition{response: true})
				}
			}
		case documentMember(member, true):
			if service.Protocol == awscatalog.RestXML {
				continue
			}
			var encoded json.RawMessage
			encoded, err = encodeJSONMember(service, member, field, documentPosition{response: true})
			if encoded != nil {
				if document == nil {
					document = make(map[string]json.RawMessage)
				}
				document[memberJSONName(member)] = encoded
			}
		default:
			return HTTPResponse{}, fmt.Errorf("%w: output %s.%s", ErrUnsupportedBinding, shape.ID, member.Name)
		}
		if err != nil {
			return HTTPResponse{}, err
		}
	}
	bodyForbidden := response.StatusCode < 200 || response.StatusCode == 204 || response.StatusCode == 205 || response.StatusCode == 304
	// A declared REST JSON output is a document even when it has no unbound
	// members. Unit means no output; body-forbidden HTTP statuses stay empty.
	if !payload && (documentMembers || service.Protocol == awscatalog.RestJSON && operation.Output != "smithy.api#Unit" && !bodyForbidden) {
		if service.Protocol == awscatalog.RestXML {
			member := awscatalog.Member{Name: xmlShapeName(shape), Target: shape.ID}
			value := reflect.ValueOf(output)
			root := true
			if operation.XMLUnwrappedOutput {
				var unwrapped *awscatalog.Member
				for i := range shape.Members {
					if documentMember(shape.Members[i], true) {
						if unwrapped != nil {
							return HTTPResponse{}, fmt.Errorf("%w: multiple unwrapped XML members", ErrUnsupportedBinding)
						}
						unwrapped = &shape.Members[i]
					}
				}
				if unwrapped == nil {
					return HTTPResponse{}, fmt.Errorf("%w: missing unwrapped XML member", ErrUnsupportedBinding)
				}
				member.Target, value, root = unwrapped.Target, fields[unwrapped.Name], false
				if nilValue(value) {
					value = reflect.ValueOf("")
				}
				member.XMLName = member.Name
			}
			response.Body, err = encodeXMLBody(service, member, value, root)
			if err != nil {
				return HTTPResponse{}, err
			}
		} else if document == nil {
			response.Body = []byte("{}")
		} else {
			response.Body, err = json.Marshal(document)
			if err != nil {
				return HTTPResponse{}, err
			}
		}
	}
	if bodyForbidden {
		if len(response.Body) != 0 || response.Stream != nil {
			return HTTPResponse{}, fmt.Errorf("HTTP status %d forbids a response body", response.StatusCode)
		}
	}
	return response, nil
}

func indirectHTTPValue(value reflect.Value) reflect.Value {
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		value = value.Elem()
	}
	return value
}

func encodeHTTPHeader(service awscatalog.Service, member awscatalog.Member, value reflect.Value) ([]string, error) {
	shape, ok := service.Shape(member.Target)
	if !ok {
		return nil, fmt.Errorf("missing generated shape %s", member.Target)
	}
	value = indirectHTTPValue(value)
	if shape.Kind == "list" || shape.Kind == "set" {
		if value.Kind() != reflect.Slice {
			return nil, outputTypeError(member.Target, value)
		}
		values := make([]string, 0, value.Len())
		for i := range value.Len() {
			if nilValue(value.Index(i)) {
				continue
			}
			element := shape.Member
			if member.TimestampFormat != "" {
				element.TimestampFormat = member.TimestampFormat
			}
			encoded, err := encodeHTTPHeader(service, element, value.Index(i))
			if err != nil {
				return nil, err
			}
			for _, text := range encoded {
				target, _ := service.Shape(element.Target)
				if (target.Kind == "string" || target.Kind == "enum") && strings.ContainsAny(text, ",\"") {
					text = strconv.Quote(text)
				}
				values = append(values, text)
			}
		}
		return values, nil
	}
	if shape.Kind == "timestamp" {
		stamp, ok := value.Interface().(time.Time)
		if !ok {
			return nil, outputTypeError(member.Target, value)
		}
		format := member.TimestampFormat
		if format == "" {
			format = shape.TimestampFormat
		}
		if format == "" || format == "http-date" {
			return []string{stamp.UTC().Format(http.TimeFormat)}, nil
		}
	}
	encoded, err := encodeValue(service, member.Target, value, member.TimestampFormat, documentPosition{})
	if err != nil {
		return nil, err
	}
	text := string(encoded)
	switch shape.Kind {
	case "string", "enum", "timestamp":
		if len(encoded) > 0 && encoded[0] == '"' {
			if err := json.Unmarshal(encoded, &text); err != nil {
				return nil, err
			}
		}
		if shape.MediaType != "" {
			text = base64.StdEncoding.EncodeToString([]byte(text))
		}
	case "boolean", "byte", "short", "integer", "long", "float", "double", "intEnum":
	default:
		return nil, fmt.Errorf("%w: %s HTTP header", ErrUnsupportedBinding, member.Target)
	}
	return []string{text}, nil
}

func encodeXMLBody(service awscatalog.Service, member awscatalog.Member, value reflect.Value, document bool) ([]byte, error) {
	shape, _ := service.Shape(member.Target)
	if !document {
		member.Name = xmlPayloadName(service, member)
	}
	if member.XMLNamespace == "" && shape.XMLNamespace == "" {
		member.XMLNamespace = service.XMLNamespace
	}
	var body bytes.Buffer
	encoder := xml.NewEncoder(&body)
	if err := encodeXMLBoundElement(encoder, service, member, value, document); err != nil {
		return nil, err
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}
