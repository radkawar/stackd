package apigatewayexec

import (
	"fmt"
	"strings"

	"stackd/internal/awswire"
)

// ValidateAccessLogFormat applies the protocol's access-log admission rules.
// HTTP APIs reject unsupported context expressions; REST and WebSocket APIs
// retain unknown expressions and render their absent values as a dash.
func ValidateAccessLogFormat(protocol, format string) error {
	prefix := ""
	if protocol != "REST" {
		prefix = "The following errors are found in Access Log Format: "
	}
	line := format
	if protocol == "REST" {
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
	}
	if strings.ContainsAny(line, "\r\n") {
		message := "Access Log format must be single line"
		if protocol == "REST" {
			message += ", new line character is allowed only at end of the format"
		}
		return invalidAccessLogFormat(fmt.Sprintf("%s%s: '%s'", prefix, message, format))
	}
	foundID := false
	var unsupported []string
	for offset := 0; offset < len(format); {
		start, end, name := accessLogVariable(format, offset, protocol == "HTTP")
		if start < 0 {
			break
		}
		offset = end
		if name == "requestId" || name == "extendedRequestId" {
			foundID = true
		}
		if protocol == "HTTP" && !httpAccessLogVariable(name) {
			unsupported = append(unsupported, format[start:end])
		}
	}
	if len(unsupported) != 0 {
		return invalidAccessLogFormat(fmt.Sprintf("The following context variables are not supported: [%s]", strings.Join(unsupported, ", ")))
	}
	if !foundID {
		return invalidAccessLogFormat(fmt.Sprintf("%sAccess Log format must include either $context.requestId or $context.extendedRequestId : '%s'", prefix, format))
	}
	return nil
}

func invalidAccessLogFormat(message string) error {
	return &awswire.Error{Code: "BadRequestException", Message: message, StatusCode: 400}
}

// RenderAccessLog substitutes $context.name and ${context.name} expressions.
// Values are keyed by the context-relative name, for example integration.status.
// This is simple substitution, not a VTL evaluator or a JSON serializer.
func RenderAccessLog(format string, values map[string]string) string {
	var result strings.Builder
	result.Grow(len(format))
	offset := 0
	for offset < len(format) {
		start, end, name := accessLogVariable(format, offset, false)
		if start < 0 {
			break
		}
		result.WriteString(format[offset:start])
		value, present := values[name]
		if !present || value == "" {
			value = "-"
		}
		result.WriteString(value)
		offset = end
	}
	result.WriteString(format[offset:])
	return result.String()
}

func accessLogVariable(format string, offset int, http bool) (start, end int, name string) {
	for offset < len(format) {
		next := strings.IndexByte(format[offset:], '$')
		if next < 0 {
			break
		}
		start = offset + next
		offset = start + 1
		braced := strings.HasPrefix(format[offset:], "{context.")
		if braced {
			end := strings.IndexByte(format[offset:], '}')
			if end >= 0 {
				end += offset
				return start, end + 1, format[offset+len("{context.") : end]
			}
			continue
		}
		if !strings.HasPrefix(format[offset:], "context.") {
			continue
		}
		begin := offset + len("context.")
		end = begin
		for end < len(format) {
			c := format[end]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' {
				end++
				continue
			}
			// Native HTTP admission includes an adjacent pipe in the variable,
			// unlike the REST/WebSocket substitution grammar.
			if http && c == '|' {
				end++
				continue
			}
			break
		}
		if end > begin {
			return start, end, format[begin:end]
		}
	}
	return -1, -1, ""
}

func httpAccessLogVariable(name string) bool {
	switch name {
	case "accountId", "apiId", "awsEndpointRequestId", "awsEndpointRequestId2",
		"customDomain.basePathMatched", "dataProcessed", "domainName", "domainPrefix",
		"error.message", "error.messageString", "error.responseType", "extendedRequestId",
		"httpMethod", "identity.accountId", "identity.caller",
		"identity.cognitoAuthenticationProvider", "identity.cognitoAuthenticationType",
		"identity.cognitoIdentityId", "identity.cognitoIdentityPoolId", "identity.principalOrgId",
		"identity.clientCert.clientCertPem", "identity.clientCert.subjectDN", "identity.clientCert.issuerDN",
		"identity.clientCert.serialNumber", "identity.clientCert.validity.notBefore", "identity.clientCert.validity.notAfter",
		"identity.sourceIp", "identity.user", "identity.userAgent", "identity.userArn",
		"integration.error", "integration.integrationStatus", "integration.latency", "integration.requestId", "integration.status",
		"integrationErrorMessage", "integrationLatency", "integrationStatus", "path", "protocol",
		"requestId", "requestTime", "requestTimeEpoch", "responseLatency", "responseLength", "routeKey", "stage", "status",
		// HTTP accepts resourcePath in the native fixture, but does not populate it.
		"resourcePath":
		return true
	}
	if !strings.HasPrefix(name, "authorizer.") || len(name) == len("authorizer.") {
		return false
	}
	for _, c := range name[len("authorizer."):] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
