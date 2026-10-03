package apigatewayexec

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

const executionLogLimit = 1024

func sensitiveExecutionParameter(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "x-api-key", "x-amz-security-token", "x-amz-credential", "x-amz-signature", "x-amz-server-side-encryption-customer-key":
		return true
	}
	return false
}

// RedactExecutionLogParameters returns a view for execution-log serialization.
// The caller's headers/query are never mutated; nonsensitive slices are shared.
func RedactExecutionLogParameters(values map[string][]string) map[string][]string {
	result := make(map[string][]string, len(values))
	for key, value := range values {
		if sensitiveExecutionParameter(key) {
			result[key] = []string{"[REDACTED]"}
		} else {
			result[key] = value
		}
	}
	return result
}

// RedactExecutionLogPayload removes credential fields from structured Gateway
// events before data tracing. Non-JSON bodies and customer body strings remain
// unchanged: data tracing can expose application data, as it does in AWS.
func RedactExecutionLogPayload(payload []byte) []byte {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var trailing any
	if decoder.Decode(&value) != nil || decoder.Decode(&trailing) != io.EOF {
		return payload
	}
	if !redactExecutionObject(value) {
		return payload
	}
	redacted, err := json.Marshal(value)
	if err != nil {
		return payload
	}
	return redacted
}

func redactExecutionObject(value any) bool {
	changed := false
	switch value := value.(type) {
	case map[string]any:
		for key, member := range value {
			switch key {
			case "headers", "multiValueHeaders", "queryStringParameters", "multiValueQueryStringParameters":
				if parameters, ok := member.(map[string]any); ok {
					for name, original := range parameters {
						if sensitiveExecutionParameter(name) {
							if _, multiple := original.([]any); multiple {
								parameters[name] = []any{"[REDACTED]"}
							} else {
								parameters[name] = "[REDACTED]"
							}
							changed = true
						}
					}
				}
			case "identity":
				if identity, ok := member.(map[string]any); ok {
					if _, present := identity["apiKey"]; present {
						identity["apiKey"] = "[REDACTED]"
						changed = true
					}
				}
			}
			if redactExecutionObject(member) {
				changed = true
			}
		}
	case []any:
		for _, member := range value {
			if redactExecutionObject(member) {
				changed = true
			}
		}
	}
	return changed
}

func executionParameters(values map[string][]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result strings.Builder
	result.WriteByte('{')
	for index, key := range keys {
		if index != 0 {
			result.WriteString(", ")
		}
		result.WriteString(key)
		result.WriteByte('=')
		if sensitiveExecutionParameter(key) {
			result.WriteString("[REDACTED]")
		} else {
			result.WriteString(strings.Join(values[key], ","))
		}
	}
	result.WriteByte('}')
	return result.String()
}

// FormatExecutionLog applies the shared REST/WebSocket 1024-byte event limit.
// requestID is Gateway-owned; truncation never splits a UTF-8 code point.
func FormatExecutionLog(requestID, message string) string {
	end := executionLogLimit - len(requestID) - len("() ")
	if len(message) > end {
		for !utf8.RuneStart(message[end]) {
			end--
		}
		message = message[:end]
	}
	return "(" + requestID + ") " + message
}

func (o *requestObservation) execution(message string) {
	o.executionLogs = append(o.executionLogs, FormatExecutionLog(o.requestID, message))
}

func (o *requestObservation) executionData(prefix string, payload []byte) {
	o.execution(prefix + string(payload[:min(len(payload), executionLogLimit)]))
}

func (o *requestObservation) traceRequest(r *http.Request, route *Route, body []byte) {
	parameters := make(map[string][]string, len(route.PathParameters))
	for key, value := range route.PathParameters {
		parameters[key] = []string{value}
	}
	o.execution("Method request path: " + executionParameters(parameters))
	o.execution("Method request query string: " + executionParameters(r.URL.Query()))
	headers := r.Header.Clone()
	headers.Set("Host", r.Host)
	o.execution("Method request headers: " + executionParameters(headers))
	o.execution("Method request body before transformations: " + string(body[:min(len(body), executionLogLimit)]))
	// TODO: Comeback emit transport request/response records only when a real
	// integration transport exposes them. The typed Lambda command boundary
	// has no AWS HTTP signing headers; inventing those would leak false evidence.
}
