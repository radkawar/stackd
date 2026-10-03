package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sfn"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type stepFunctionsHTTPFixture struct {
	Account, Region, Endpoint string
	Observations              []awsNativeObservation
	Followups                 []stepFunctionsHTTPFixture `json:"followup_attempts"`
}

type stepFunctionsHTTPReplay struct {
	clients   cloudClients
	outbound  *http.Client
	fixture   stepFunctionsHTTPFixture
	bindings  map[string]string
	requests  atomic.Int64
	tokens    atomic.Int64
	flaky     atomic.Int64
	cancelled chan struct{}
	started   chan string
	onRequest func(string)
}

func TestStepFunctionsNativeHTTPConnections(t *testing.T) {
	var fixture stepFunctionsHTTPFixture
	awsReadFixture(t, "stepfunctions/http_connections.json", &fixture)
	if len(fixture.Followups) != 2 {
		t.Fatal("native HTTP fixture is missing the immutable-role controls")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, part := range []struct {
			name    string
			fixture stepFunctionsHTTPFixture
		}{{"composition", fixture}, {"immutable-role", fixture.Followups[1]}} {
			t.Run(backend+"/"+part.name, func(t *testing.T) {
				r := &stepFunctionsHTTPReplay{fixture: part.fixture, bindings: map[string]string{}, cancelled: make(chan struct{}, 1), started: make(chan string, 2)}
				provider := httptest.NewTLSServer(http.HandlerFunc(r.serveHTTP))
				defer provider.Close()
				r.outbound = provider.Client()
				r.bindings[strings.TrimSuffix(part.fixture.Endpoint, "/")] = provider.URL
				var reopen func() cloudClients
				var source clock.Clock
				r.clients, reopen = retainedCloud(t, backend, stackd.Config{AccountID: part.fixture.Account, OutboundHTTP: r.outbound}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
					config.Clock = source
					return startPublicCloud(t, config)
				})
				for _, row := range part.fixture.Observations {
					op := stepFunctionsOperation(row.Operation)
					if op == "startsyncexecution" {
						if part.name == "composition" && strings.HasPrefix(row.Label, "iam-") {
							continue // Warm role mutations are explicitly not authoritative.
						}
						if row.Label == "method-head" {
							continue // Lambda Function URL rejected HEAD with a body before the handler.
						}
						if !t.Run(row.Label, func(t *testing.T) { r.execute(t, row) }) {
							return
						}
						continue
					}
					setup := row.Service == "events" && (op == "createconnection" || op == "describeconnection" && strings.HasPrefix(row.Label, "connection-state-")) ||
						row.Service == "iam" && (row.Label == "create-role-full" || row.Label == "policy-full") ||
						op == "createstatemachine"
					if !setup {
						continue
					}
					result := r.call(t, row.Service, row.Operation, r.replace(row.Input))
					if row.Service == "events" {
						var native map[string]any
						awsDecodeJSON(t, row.Result.Output, &native)
						actual := stepFunctionsSDKObject(t, result)
						for _, key := range []string{"ConnectionArn", "SecretArn"} {
							if arn, ok := native[key].(string); ok {
								local, ok := actual[key].(string)
								if !ok || local == "" {
									t.Fatal("missing generated", key, actual)
								}
								r.bindings[arn] = local
							}
						}
					}
				}
				if part.name == "composition" {
					before := r.tokens.Load()
					r.clients = reopen()
					for _, row := range part.fixture.Observations {
						if row.Label == "oauth-json" || row.Label == "basic-merge-json" {
							r.execute(t, row)
						}
					}
					if r.tokens.Load() <= before {
						t.Fatal("reopened OAuth connection did not fetch a real provider token")
					}
					r.transitions(t, provider.URL, func() *clock.Manual {
						manual := clock.NewManual(r.clients.server.Config.Handler.(*stackd.Stack).ServiceTime())
						source = manual
						r.clients = reopen()
						return manual
					})
				} else {
					// The fixture withholds endpoint access; also prove the same
					// immutable policy's method condition against an allowed URL.
					for _, row := range part.fixture.Observations {
						if row.Label != "fixed-role-working-control-before" {
							continue
						}
						input := strings.ReplaceAll(string(r.replace(row.Input)), `\"method\": \"POST\"`, `\"method\": \"PATCH\"`)
						before := r.requests.Load()
						result := r.call(t, "stepfunctions", "start-sync-execution", json.RawMessage(input)).(*sfn.StartSyncExecutionOutput)
						if aws.ToString(result.Error) != "States.Http.AccessDenied" || r.requests.Load() != before {
							t.Fatalf("HTTP method condition bypassed: %+v", result)
						}
					}
				}
				t.Log("Compared native task outcomes, credential-bearing requests, exact duplicate-header precedence, percent encoding and response types. Projected generated ARN/endpoint bindings, HTTP header casing, JSON member/query/form key order and Lambda transport-only response metadata; skipped warm-role observations and infrastructure-only HEAD/body rejection.")
			})
		}
	}
}

// This is the fixture's owned provider implemented as a real TLS endpoint. No
// task handler or transport is replaced. The token route checks actual client
// credentials and issues its token only for the captured OAuth grant.
func (r *stepFunctionsHTTPReplay) serveHTTP(w http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if request.URL.Path == "/oauth" {
		values, err := url.ParseQuery(string(body))
		if err != nil || request.Method != "POST" || values.Get("client_id") != "owned-client" || values.Get("client_secret") != "owned-client-secret" || values.Get("grant_type") != "client_credentials" || values.Get("scope") != "owned-echo" || request.Header.Get("x-owned-oauth") != "token-request" {
			http.Error(w, "invalid OAuth credentials or grant", http.StatusUnauthorized)
			return
		}
		r.tokens.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"owned-inert-oauth-token","token_type":"Bearer","expires_in":3600}`)
		return
	}
	r.requests.Add(1)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-owned-response", "echo-v1")
	switch request.URL.Path {
	case "/text":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("x-owned-response", "plain-v1")
		io.WriteString(w, "owned plain response")
		return
	case "/binary":
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, "owned inert bytes")
		return
	case "/large":
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat("x", 262145))
		return
	case "/invalid-utf8":
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte{0xff})
		return
	case "/cancel", "/task-cancel":
		r.started <- request.URL.Path
		<-request.Context().Done()
		select {
		case r.cancelled <- struct{}{}:
		default:
		}
		return
	case "/flaky":
		if r.flaky.Add(1) == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(418)
		}
		return
	}
	if strings.HasPrefix(request.URL.Path, "/status/") {
		status, _ := strconv.Atoi(strings.TrimPrefix(request.URL.Path, "/status/"))
		w.WriteHeader(status)
		if status == 204 {
			return
		}
	}
	if request.Method == "HEAD" {
		return
	}
	headers := make(map[string]string)
	for name, values := range request.Header {
		headers[strings.ToLower(name)] = strings.Join(values, ",")
	}
	headers["host"] = request.Host
	json.NewEncoder(w).Encode(map[string]any{"method": request.Method, "path": request.URL.Path, "rawQueryString": request.URL.RawQuery, "headers": headers, "body": string(body)})
}

func (r *stepFunctionsHTTPReplay) replace(input json.RawMessage) json.RawMessage {
	text := string(input)
	for from, to := range r.bindings {
		text = strings.ReplaceAll(text, from, to)
	}
	return json.RawMessage(text)
}

func (r *stepFunctionsHTTPReplay) call(t *testing.T, service, operation string, input json.RawMessage) any {
	t.Helper()
	config := aws.Config{Region: r.fixture.Region, HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider(r.fixture.Account, "test", "")}
	endpoint := aws.String(r.clients.server.URL)
	var client any
	switch service {
	case "events":
		client = eventbridge.NewFromConfig(config, func(o *eventbridge.Options) { o.BaseEndpoint = endpoint })
	case "iam":
		client = iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = endpoint })
	case "stepfunctions":
		client = sfn.NewFromConfig(config, func(o *sfn.Options) {
			o.BaseEndpoint = endpoint
			o.APIOptions = append(o.APIOptions, stepFunctionsLocalEndpoint)
		})
	default:
		t.Fatal("unknown HTTP fixture service", service)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	type reply struct {
		output any
		err    error
	}
	done := make(chan reply, 1)
	go func() { output, err := awstest.CallSDK(ctx, client, operation, input); done <- reply{output, err} }()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case result := <-done:
			if result.err != nil {
				t.Fatal(operation, result.err)
			}
			return result.output
		case path := <-r.started:
			if r.onRequest != nil {
				r.onRequest(path)
			}
		case <-ticker.C:
			if _, err := r.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(operation, ctx.Err())
		}
	}
}

func (r *stepFunctionsHTTPReplay) execute(t *testing.T, row awsNativeObservation) {
	t.Helper()
	var want struct{ Status, Error, Output string }
	awsDecodeJSON(t, r.replace(row.Result.Output), &want)
	before := r.requests.Load()
	actual := r.call(t, row.Service, row.Operation, r.replace(row.Input)).(*sfn.StartSyncExecutionOutput)
	if string(actual.Status) != want.Status || aws.ToString(actual.Error) != want.Error {
		t.Fatalf("%s: native %s/%s, local %s/%s: %s", row.Label, want.Status, want.Error, actual.Status, aws.ToString(actual.Error), aws.ToString(actual.Cause))
	}
	if want.Status != "SUCCEEDED" {
		if strings.Contains(want.Error, "AccessDenied") || row.Label == "prohibited-task-authorization-header" || row.Label == "string-body-connection-merge-error" {
			if r.requests.Load() != before {
				t.Fatal("failed authorization/validation sent a request to the provider")
			}
		}
		return
	}
	var native, local map[string]any
	awsDecodeJSON(t, json.RawMessage(want.Output), &native)
	awsDecodeJSON(t, json.RawMessage(aws.ToString(actual.Output)), &local)
	stepFunctionsHTTPProjection(t, native)
	stepFunctionsHTTPProjection(t, local)
	if !reflect.DeepEqual(native, local) {
		a, _ := json.Marshal(native)
		b, _ := json.Marshal(local)
		t.Fatalf("%s HTTP result differs\nnative: %s\nlocal:  %s", row.Label, a, b)
	}
}

func stepFunctionsHTTPProjection(t *testing.T, result map[string]any) {
	t.Helper()
	headers, ok := result["Headers"].(map[string]any)
	if !ok {
		t.Fatal("HTTP result has no Headers object", result)
	}
	projected := make(map[string]any)
	for name, value := range headers {
		array, ok := value.([]any)
		if !ok {
			t.Fatal("HTTP response header is not an array", name, value)
		}
		for _, item := range array {
			if _, ok := item.(string); !ok {
				t.Fatal("HTTP header is not a string", item)
			}
		}
		name = strings.ToLower(name)
		if name == "content-type" || name == "x-owned-response" {
			projected[name] = value
		}
	}
	result["Headers"] = projected
	body, ok := result["ResponseBody"].(map[string]any)
	if !ok {
		return
	}
	requestHeaders := body["headers"].(map[string]any)
	for key := range requestHeaders {
		switch key {
		case "authorization", "x-owned-api-key", "x-shared", "x-secret", "x-task-only", "content-type", "content-length", "range", "user-agent":
		default:
			delete(requestHeaders, key)
		}
	}
	body["rawQueryString"] = stepFunctionsHTTPEncodedPairs(t, body["rawQueryString"].(string))
	text := body["body"].(string)
	if requestHeaders["content-type"] == "application/x-www-form-urlencoded" {
		body["body"] = stepFunctionsHTTPEncodedPairs(t, text)
	} else if json.Valid([]byte(text)) {
		var decoded any
		awsDecodeJSON(t, json.RawMessage(text), &decoded)
		body["body"] = decoded
	}
}

func stepFunctionsHTTPEncodedPairs(t *testing.T, text string) []string {
	t.Helper()
	if strings.Contains(text, "+") {
		t.Fatal("form/query used + rather than native %20", text)
	}
	pairs := strings.Split(text, "&")
	slices.Sort(pairs)
	return pairs
}

func (r *stepFunctionsHTTPReplay) transitions(t *testing.T, endpoint string, freeze func() *clock.Manual) {
	t.Helper()
	var machine, connection string
	for _, row := range r.fixture.Observations {
		if row.Label == "apikey-json" {
			var input struct{ StateMachineArn, Input string }
			awsDecodeJSON(t, r.replace(row.Input), &input)
			machine = input.StateMachineArn
			var parameters struct{ Connection string }
			awsDecodeJSON(t, json.RawMessage(input.Input), &parameters)
			connection = parameters.Connection
		}
	}
	definition := fmt.Sprintf(`{"StartAt":"Call","States":{"Call":{"Type":"Task","Resource":"arn:aws:states:::http:invoke","Parameters":{"ApiEndpoint.$":"$.endpoint","Method":"POST","InvocationConfig":{"ConnectionArn":%q}},"Retry":[{"ErrorEquals":["States.Http.StatusCode.503"],"IntervalSeconds":1,"MaxAttempts":1}],"Catch":[{"ErrorEquals":["States.Http.StatusCode.418"],"Next":"Caught"}],"End":true},"Caught":{"Type":"Pass","End":true}}}`, connection)
	update, _ := json.Marshal(map[string]string{"stateMachineArn": machine, "definition": definition})
	r.call(t, "stepfunctions", "update-state-machine", update)
	run := func(path string) *sfn.StartSyncExecutionOutput {
		input, _ := json.Marshal(map[string]string{"endpoint": endpoint + path})
		request, _ := json.Marshal(map[string]string{"stateMachineArn": machine, "input": string(input)})
		return r.call(t, "stepfunctions", "start-sync-execution", request).(*sfn.StartSyncExecutionOutput)
	}
	caught := run("/flaky")
	var failure struct{ Error, Cause string }
	awsDecodeJSON(t, json.RawMessage(aws.ToString(caught.Output)), &failure)
	if caught.Status != "SUCCEEDED" || failure.Error != "States.Http.StatusCode.418" || failure.Cause != "" || r.flaky.Load() != 2 {
		t.Fatalf("HTTP status did not flow through retry/catch: %+v, requests=%d", caught, r.flaky.Load())
	}
	for _, probe := range []struct{ path, code string }{{"/large", "States.DataLimitExceeded"}, {"/invalid-utf8", "States.Runtime"}} {
		out := run(probe.path)
		if aws.ToString(out.Error) != probe.code {
			t.Fatalf("%s: %+v", probe.path, out)
		}
	}
	// A short injected client deadline exercises the real socket timeout path;
	// the native fixture did not wait out the documented 60-second ceiling.
	r.outbound.Timeout = 100 * time.Millisecond
	socket := run("/cancel")
	r.outbound.Timeout = 0
	if aws.ToString(socket.Error) != "States.Http.Socket" {
		t.Fatalf("socket timeout: %+v", socket)
	}
	select {
	case <-r.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("socket timeout did not close the real outbound request")
	}
	definition = strings.Replace(definition, `"Type":"Task"`, `"Type":"Task","TimeoutSeconds":1`, 1)
	update, _ = json.Marshal(map[string]string{"stateMachineArn": machine, "definition": definition})
	r.call(t, "stepfunctions", "update-state-machine", update)
	// Task deadlines include authority and secret resolution. Freeze service
	// time across those steps, and expire the task only after the real receiver
	// has admitted it. A wall-time second could legitimately expire pre-request
	// under SQLite/race load and therefore have no socket left to cancel.
	source := freeze()
	r.onRequest = func(path string) {
		if path == "/task-cancel" {
			r.onRequest = nil
			if err := source.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
		}
	}
	out := run("/task-cancel")
	if aws.ToString(out.Error) != "States.Timeout" {
		t.Fatalf("task deadline: %+v", out)
	}
	select {
	case <-r.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("task cancellation did not close the real outbound request")
	}
}
