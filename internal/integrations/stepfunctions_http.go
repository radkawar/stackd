package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/stepfunctions"
)

// StepFunctionsConnections resolves credentials with the actual execution-role
// context. The connection owner also enforces caller access to its managed secret.
type StepFunctionsConnections interface {
	ResolveConnection(context.Context, string) (eventbridge.ConnectionParameters, *awswire.Error)
}

const stepFunctionsHTTPDataLimit = 262144

func (t *StepFunctionsTasks) runHTTPTask(ctx context.Context, task stepfunctions.TaskRecord, revision stepfunctions.RevisionRecord) (stepfunctions.TaskOutcome, error) {
	if err := ctx.Err(); err != nil {
		return stepfunctions.TaskOutcome{}, err
	}
	if task.Kind == "sync" || task.Kind == "callback" {
		return stepfunctionsHTTPFailure("States.Runtime", "HTTP tasks support only the Request Response integration pattern."), nil
	}
	parameters, err := stepFunctionsJSONObject(task.Parameters)
	if err != nil {
		return stepfunctionsHTTPFailure("States.Runtime", err.Error()), nil
	}
	var endpoint, method string
	if json.Unmarshal(parameters["ApiEndpoint"], &endpoint) != nil || json.Unmarshal(parameters["Method"], &method) != nil {
		return stepfunctionsHTTPFailure("States.Runtime", "ApiEndpoint and Method must be strings."), nil
	}
	address, err := url.Parse(endpoint)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil || address.Fragment != "" {
		return stepfunctionsHTTPFailure("States.Runtime", "ApiEndpoint must be a valid HTTPS URL without user information or a fragment."), nil
	}
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD":
	default:
		return stepfunctionsHTTPFailure("States.Runtime", "Method must be GET, POST, PUT, DELETE, PATCH, OPTIONS, or HEAD."), nil
	}
	config, present := parameters["InvocationConfig"]
	if legacy, ok := parameters["Authentication"]; ok {
		if present {
			return stepfunctionsHTTPFailure("States.Runtime", "Specify either Authentication or InvocationConfig, not both."), nil
		}
		config = legacy
	}
	var connection struct{ ConnectionArn string }
	if json.Unmarshal(config, &connection) != nil || connection.ConnectionArn == "" {
		return stepfunctionsHTTPFailure("States.Runtime", "A ConnectionArn is required in Authentication or InvocationConfig."), nil
	}
	if t.Roles.Authorizer == nil || t.Connections == nil {
		return stepfunctions.TaskOutcome{}, errors.New("HTTP task connection and authorization dependencies are not configured")
	}
	if wire := t.Roles.Authorizer.Authorize(ctx, authorization.Request{
		Action: "states:InvokeHTTPEndpoint", ResourceARN: revision.Machine.ARN(),
		Context: map[string][]string{"states:HTTPEndpoint": {endpoint}, "states:HTTPMethod": {method}},
	}); wire != nil {
		if wire.StatusCode >= 500 {
			return stepfunctions.TaskOutcome{}, wire
		}
		return stepfunctionsHTTPFailure("States.Http.AccessDenied", "AWS Step Functions is not authorized to perform states:InvokeHTTPEndpoint on API Endpoint "+endpoint+". Ensure that the StateMachine role contains the states:InvokeHTTPEndpoint permission for the given API Endpoint"), nil
	}
	var headers map[string]any
	if raw, exists := parameters["Headers"]; exists {
		if err := json.Unmarshal(raw, &headers); err != nil || headers == nil {
			return stepfunctionsHTTPFailure("States.Runtime", "Headers must be an object."), nil
		}
	}
	for key := range headers {
		if stepFunctionsHTTPForbiddenHeader(key) {
			return stepfunctionsHTTPFailure("States.Runtime", "The Headers field contains an unsupported header: "+key), nil
		}
	}
	resolved, wire := t.Connections.ResolveConnection(ctx, connection.ConnectionArn)
	if wire != nil {
		return stepfunctionsHTTPFailure("Events."+wire.Code, wire.Message), nil
	}
	body, err := stepFunctionsHTTPBody(parameters, resolved.Body)
	if err != nil {
		return stepfunctionsHTTPFailure("States.Runtime", err.Error()), nil
	}
	if len(body) > stepFunctionsHTTPDataLimit {
		return stepfunctionsHTTPFailure("States.DataLimitExceeded", "HTTP request body exceeds the maximum allowed size of 262144 bytes."), nil
	}
	query, err := stepFunctionsHTTPQuery(parameters["QueryParameters"], resolved.Query)
	if err != nil {
		return stepfunctionsHTTPFailure("States.Runtime", err.Error()), nil
	}
	if query != "" {
		if address.RawQuery != "" {
			address.RawQuery += "&"
		}
		address.RawQuery += query
	}
	// Bound the whole exchange, including reading the response. A shorter caller
	// deadline remains authoritative and cancellation returns to the task owner.
	exchange, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := http.DefaultClient
	if t.HTTPClient != nil {
		client = t.HTTPClient
	}
	outbound := *client
	// A redirect is another endpoint and must not bypass the IAM endpoint check
	// or send connection credentials to an unapproved host.
	outbound.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	outbound.Jar = nil
	for attempt := 0; ; attempt++ {
		request, err := http.NewRequestWithContext(exchange, method, address.String(), bytes.NewReader(body))
		if err != nil {
			return stepfunctionsHTTPFailure("States.Runtime", err.Error()), nil
		}
		if err := stepFunctionsHTTPHeaders(request.Header, headers, resolved.Headers); err != nil {
			return stepfunctionsHTTPFailure("States.Runtime", err.Error()), nil
		}
		request.Header.Set("User-Agent", "Amazon|StepFunctions|HttpInvoke|"+awsctx.FromContext(ctx).Region)
		request.Header.Set("Range", "bytes=0-262144")
		if request.Header.Get("Content-Type") == "" {
			request.Header.Set("Content-Type", "application/json; charset=UTF-8")
		}
		if trace := awsctx.FromContext(ctx).TraceHeader; trace != "" {
			request.Header.Set("X-Amzn-Trace-Id", trace)
		}
		response, err := outbound.Do(request)
		if err != nil {
			return stepFunctionsHTTPTransportFailure(ctx, err)
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			if refresh, ok := t.Connections.(interface {
				ReauthorizeConnection(context.Context, string) (eventbridge.ConnectionParameters, *awswire.Error)
			}); ok {
				refreshed, failure := refresh.ReauthorizeConnection(exchange, connection.ConnectionArn)
				if failure != nil {
					response.Body.Close()
					return stepfunctionsHTTPFailure("Events."+failure.Code, failure.Message), nil
				}
				if !maps.Equal(resolved.Headers, refreshed.Headers) {
					response.Body.Close()
					resolved = refreshed
					continue
				}
			}
		}
		outcome, err := stepFunctionsHTTPResponse(response, method)
		response.Body.Close()
		if err != nil {
			return stepFunctionsHTTPTransportFailure(ctx, err)
		}
		return outcome, nil
	}
}

func stepfunctionsHTTPFailure(name, cause string) stepfunctions.TaskOutcome {
	return stepfunctions.TaskOutcome{Error: name, Cause: cause}
}

func stepFunctionsHTTPTransportFailure(ctx context.Context, err error) (stepfunctions.TaskOutcome, error) {
	if ctx.Err() != nil {
		return stepfunctions.TaskOutcome{}, ctx.Err()
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return stepfunctionsHTTPFailure("States.Http.Socket", "HTTP request timed out."), nil
	}
	return stepfunctionsHTTPFailure("States.Http.Socket", "HTTP request failed: "+err.Error()), nil
}

func stepFunctionsHTTPForbiddenHeader(name string) bool {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "x-forwarded-") || strings.HasPrefix(name, "x-amz-") || strings.HasPrefix(name, "x-amzn-") {
		return true
	}
	switch name {
	case "a-im", "accept-charset", "accept-datetime", "accept-encoding", "authorization", "cache-control", "connection", "content-encoding", "content-md5", "date", "expect", "forwarded", "from", "host", "http2-settings", "if-match", "if-modified-since", "if-none-match", "if-range", "if-unmodified-since", "max-forwards", "origin", "pragma", "proxy-authorization", "referer", "server", "te", "trailer", "transfer-encoding", "upgrade", "via", "warning":
		return true
	}
	return false
}

func stepFunctionsHTTPHeaders(out http.Header, task map[string]any, connection map[string]string) error {
	// Merge exact keys before HTTP's case-insensitive canonicalization. Different
	// spellings survive as multiple values, with the connection values first.
	for _, key := range slices.Sorted(maps.Keys(connection)) {
		out.Add(key, connection[key])
	}
	for _, key := range slices.Sorted(maps.Keys(task)) {
		if _, overridden := connection[key]; overridden {
			continue
		}
		switch value := task[key].(type) {
		case string:
			out.Add(key, value)
		case []any:
			for _, item := range value {
				text, ok := item.(string)
				if !ok {
					return fmt.Errorf("header %s must contain strings", key)
				}
				out.Add(key, text)
			}
		default:
			return fmt.Errorf("header %s must be a string or array of strings", key)
		}
	}
	return nil
}

func stepFunctionsHTTPBody(parameters map[string]json.RawMessage, connection map[string]string) ([]byte, error) {
	var transform struct {
		RequestBodyEncoding    string
		RequestEncodingOptions struct{ ArrayFormat string }
	}
	if raw, exists := parameters["Transform"]; exists {
		if err := json.Unmarshal(raw, &transform); err != nil {
			return nil, errors.New("transform must specify valid request encoding options")
		}
	}
	if transform.RequestBodyEncoding != "" && transform.RequestBodyEncoding != "NONE" && transform.RequestBodyEncoding != "URL_ENCODED" {
		return nil, errors.New("RequestBodyEncoding must be NONE or URL_ENCODED")
	}
	style := transform.RequestEncodingOptions.ArrayFormat
	switch style {
	case "":
		style = "INDICES"
	case "INDICES", "REPEAT", "COMMAS", "BRACKETS":
	default:
		return nil, errors.New("ArrayFormat must be INDICES, REPEAT, COMMAS, or BRACKETS")
	}
	raw, present := parameters["RequestBody"]
	if !present && len(connection) == 0 {
		return nil, nil
	}
	var body any
	if present {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&body); err != nil {
			return nil, err
		}
	}
	if len(connection) != 0 {
		object, ok := body.(map[string]any)
		if !present {
			object, ok = make(map[string]any), true
		}
		if !ok {
			return nil, errors.New("cannot merge connection body authorization parameters with request body")
		}
		for key, value := range connection {
			object[key] = value
		}
		body = object
	}
	if text, ok := body.(string); ok {
		if transform.RequestBodyEncoding == "URL_ENCODED" {
			return []byte(stepFunctionsHTTPEscape(text)), nil
		}
		return []byte(text), nil
	}
	if transform.RequestBodyEncoding == "URL_ENCODED" {
		values := make(url.Values)
		stepFunctionsHTTPForm(values, "", body, style)
		return []byte(strings.ReplaceAll(values.Encode(), "+", "%20")), nil
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(body); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

func stepFunctionsHTTPQuery(raw json.RawMessage, connection map[string]string) (string, error) {
	object := make(map[string]any)
	if len(raw) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil || object == nil {
			return "", errors.New("QueryParameters must be an object")
		}
	}
	for key, value := range connection {
		object[key] = value
	}
	values := make(url.Values)
	stepFunctionsHTTPForm(values, "", object, "REPEAT")
	return strings.ReplaceAll(values.Encode(), "+", "%20"), nil
}

func stepFunctionsHTTPEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func stepFunctionsHTTPForm(values url.Values, key string, value any, style string) {
	switch value := value.(type) {
	case map[string]any:
		for _, name := range slices.Sorted(maps.Keys(value)) {
			child := name
			if key != "" {
				child = key + "[" + name + "]"
			}
			stepFunctionsHTTPForm(values, child, value[name], style)
		}
	case []any:
		if style == "COMMAS" {
			parts := make([]string, len(value))
			for i, item := range value {
				parts[i] = stepFunctionsHTTPScalar(item)
			}
			values.Add(key, strings.Join(parts, ","))
			return
		}
		for i, item := range value {
			child := key
			if style == "INDICES" {
				child += "[" + strconv.Itoa(i) + "]"
			} else if style == "BRACKETS" {
				child += "[]"
			}
			stepFunctionsHTTPForm(values, child, item, style)
		}
	default:
		values.Add(key, stepFunctionsHTTPScalar(value))
	}
}

func stepFunctionsHTTPScalar(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func stepFunctionsHTTPResponse(response *http.Response, method string) (stepfunctions.TaskOutcome, error) {
	statusText := http.StatusText(response.StatusCode)
	// Native HTTP tasks do not assign a reason phrase to RFC 2324's 418.
	if response.StatusCode == 418 {
		statusText = ""
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return stepfunctionsHTTPFailure("States.Http.StatusCode."+strconv.Itoa(response.StatusCode), statusText), nil
	}
	output := map[string]any{"Headers": response.Header, "StatusCode": response.StatusCode, "StatusText": statusText}
	if method != http.MethodHead && response.StatusCode != http.StatusNoContent {
		contentType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if contentType == "application/octet-stream" || strings.HasPrefix(contentType, "image/") || strings.HasPrefix(contentType, "audio/") || strings.HasPrefix(contentType, "video/") {
			return stepfunctionsHTTPFailure("States.Runtime", "Unsupported response content-type '"+contentType+"'. Please see documentation for list of unsupported content-types."), nil
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, stepFunctionsHTTPDataLimit+1))
		if err != nil {
			return stepfunctions.TaskOutcome{}, err
		}
		if len(body) > stepFunctionsHTTPDataLimit {
			return stepfunctionsHTTPFailure("States.DataLimitExceeded", "HTTP response exceeds the maximum allowed size of 262144 bytes."), nil
		}
		if !utf8.Valid(body) {
			return stepfunctionsHTTPFailure("States.Runtime", "HTTP response body is not a valid UTF-8 string."), nil
		}
		if len(body) != 0 {
			var value any = string(body)
			if contentType == "application/json" || strings.HasSuffix(contentType, "+json") {
				decoder := json.NewDecoder(bytes.NewReader(body))
				decoder.UseNumber()
				if json.Valid(body) {
					if err := decoder.Decode(&value); err != nil {
						return stepfunctionsHTTPFailure("States.Runtime", "HTTP response body contains invalid JSON."), nil
					}
				}
			}
			output["ResponseBody"] = value
		}
	}
	encoded, err := json.Marshal(output)
	return stepfunctions.TaskOutcome{Output: string(encoded)}, err
}
