package stackd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/gobwas/ws"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type gatewayWSAuthorizerFixture struct {
	Account, Region string
	HandlerSource   string `json:"handler_source"`
	Owned           struct {
		API      string `json:"http_api"`
		LogGroup string `json:"log_group"`
	}
	Observations []gatewaySDKObservation
	Sockets      []gatewayWSAuthorizerSocket `json:"websocket_observations"`
	Connections  map[string]struct {
		Marker, Phase      string
		ConfigurationPhase string `json:"configuration_phase"`
	}
	Scenarios []struct {
		Marker, Connection, Phase string
		ReceiveLabel              string `json:"receive_label"`
	}
	Logs                 []struct{ Record gatewayWSAuthorizerRecord } `json:"invocation_logs"`
	ValidationExpression *gatewayWSAuthorizerFixture                  `json:"validation_expression_capture"`
	EmptyRequestShape    *gatewayWSAuthorizerFixture                  `json:"empty_request_shape_capture"`
	IdentityContext      *gatewayWSAuthorizerFixture                  `json:"identity_context_capture"`
	MissingStageCapture  *gatewayWSAuthorizerFixture                  `json:"missing_stage_identity_capture"`
	StageVariableUpdate  *gatewayWSAuthorizerFixture                  `json:"stage_variable_update_capture"`
	RouteUpdateStatus    *gatewayWSAuthorizerFixture                  `json:"route_update_status_capture"`
	IdentityContextCases []struct {
		Phase             string
		PositiveReadiness bool `json:"positive_readiness"`
	} `json:"identity_context_cases"`
	MissingStageIdentity struct {
		Samples []struct {
			Connection string
			Status     int
		}
	} `json:"missing_stage_identity"`
}

type gatewayWSAuthorizerSocket struct {
	Label, Operation, Connection string
	StartedAt                    time.Time `json:"started_at"`
	Request                      struct {
		URL, Origin, Text, Base64 string
		Headers                   [][]string
		Opcode                    ws.OpCode
		TimeoutSeconds            float64 `json:"timeout_seconds"`
		CloseCode                 uint16  `json:"close_code"`
		CloseReason               string  `json:"close_reason"`
	}
	Result struct {
		Status                int
		Headers               map[string]string
		Outcome, Text, Base64 string
		Opcode                ws.OpCode
		Body                  struct{ Base64 string }
	}
}

type gatewayWSAuthorizerRecord struct {
	ProbeKind               string `json:"probe_kind"`
	Kind, Invocation, Mode  string
	Marker                  any
	Event, Response, Raises map[string]any
}

type gatewayWSAuthorizerFrame struct {
	actual, native []byte
}

func TestAPIGatewayNativeWebSocketAuthorizers(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real WebSocket authorizer runtimes")
	}
	var fixture gatewayWSAuthorizerFixture
	awsReadFixture(t, "apigateway/websocket_lambda_authorizers.json", &fixture)
	for _, capture := range []struct {
		name    string
		fixture *gatewayWSAuthorizerFixture
	}{
		{"timeline", &fixture},
		{"validation_expression", fixture.ValidationExpression},
		{"empty_request_shape", fixture.EmptyRequestShape},
		{"identity_context", fixture.IdentityContext},
		{"missing_stage_identity", fixture.MissingStageCapture},
		{"stage_variable_update", fixture.StageVariableUpdate},
		{"route_update_status", fixture.RouteUpdateStatus},
	} {
		if capture.fixture == nil {
			t.Fatalf("missing independent native %s capture", capture.name)
		}
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(capture.name+"/"+backend, func(t *testing.T) {
				gatewayReplayWSAuthorizers(t, backend, *capture.fixture)
			})
		}
	}
}

func gatewayReplayWSAuthorizers(t *testing.T, backend string, fixture gatewayWSAuthorizerFixture) {
	source := clock.NewManual(fixture.Observations[0].StartedAt)
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	config := func() aws.Config {
		return aws.Config{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1}
	}
	selected := map[string]bool{}
	markers := map[string]bool{}
	var excluded []string
	// Replay one final rejection per settled negative source, not its regional
	// transition or repeated sampling. Restored positive controls remain separate.
	for _, identity := range fixture.IdentityContextCases {
		if identity.PositiveReadiness {
			continue
		}
		var last string
		for _, row := range fixture.Sockets {
			if row.Operation == "connect" && fixture.Connections[row.Connection].ConfigurationPhase == identity.Phase {
				last = ""
				if row.Result.Status == http.StatusUnauthorized {
					last = row.Connection
				}
			}
		}
		if last != "" {
			selected[last] = true
		}
	}
	if samples := fixture.MissingStageIdentity.Samples; len(samples) != 0 {
		last := samples[len(samples)-1]
		if last.Status != http.StatusUnauthorized {
			t.Fatal("missing-variable capture has no final native rejection")
		}
		selected[last.Connection] = true
	}
	for name, connection := range fixture.Connections {
		switch {
		case selected[name]:
			markers[connection.Marker] = true
		case connection.Phase == "readiness" || connection.Phase == "transition":
			excluded = append(excluded, name+" (readiness/propagation)")
		case name == "identity-mixed-case-header":
			// This exact case captures aUtHoRiZaTiOn in customer events.
			// net/http loses that literal spelling. Do not lowercase all headers
			// and silently claim projection parity for this known limitation.
			excluded = append(excluded, name+" (literal header spelling unsupported)")
		case connection.Phase == "semantic":
			selected[name], markers[connection.Marker] = true, true
		default:
			t.Fatalf("unclassified native connection %s: %+v", name, connection)
		}
	}
	receives := map[string]string{}
	for _, scenario := range fixture.Scenarios {
		if selected[scenario.Connection] {
			markers[scenario.Marker] = true
			receives[scenario.ReceiveLabel] = scenario.Marker
		}
	}
	// Select the native disconnects by their genuine connect identity, not by
	// their nil marker. All selected authorizer failures remain in the oracle.
	nativeConnections := map[string]bool{}
	for _, log := range fixture.Logs {
		if marker, ok := log.Record.Marker.(string); ok && markers[marker] {
			nativeConnections[log.Record.Event["requestContext"].(map[string]any)["connectionId"].(string)] = true
		}
	}
	var expected []gatewayWSAuthorizerRecord
	for _, log := range fixture.Logs {
		record := log.Record
		request := record.Event["requestContext"].(map[string]any)
		marker, _ := record.Marker.(string)
		if markers[marker] || request["eventType"] == "DISCONNECT" && nativeConnections[request["connectionId"].(string)] {
			expected = append(expected, record)
		}
	}
	// Native stage updates propagate independently of held sockets. Retain all
	// actions and authorization assertions, but replay transient old stage maps
	// against the acknowledged configuration rather than reproducing AWS lag.
	configuredStages := map[string]map[string]any{}
	for _, record := range expected {
		request := record.Event["requestContext"].(map[string]any)
		at := time.UnixMilli(int64(request["requestTimeEpoch"].(float64)))
		var configured map[string]any
		for _, row := range fixture.Observations {
			if row.StartedAt.After(at) || row.Result.Code != "Success" || row.Operation != "CreateStage" && row.Operation != "UpdateStage" {
				continue
			}
			configured, _ = row.Result.Output["StageVariables"].(map[string]any)
		}
		if len(configured) != 0 && !reflect.DeepEqual(record.Event["stageVariables"], configured) {
			configuredStages[record.Invocation] = configured
			excluded = append(excluded, record.Invocation+" (transient stage-variable projection; acknowledged configuration asserted)")
		}
	}
	type step struct {
		at     time.Time
		index  int
		socket bool
	}
	var steps []step
	for i, row := range fixture.Observations {
		switch {
		case strings.HasPrefix(row.Label, "cleanup-"), strings.HasPrefix(row.Label, "absence-"), row.Service == "logs" && row.Operation != "CreateLogGroup":
			continue // AWS evidence collection/cleanup, not execution semantics.
		case row.Operation == "GetFunctionConfiguration", row.Operation == "CreateFunction" && row.Result.Code != "Success":
			excluded = append(excluded, row.Label+" (Lambda/IAM readiness)")
			continue
		}
		steps = append(steps, step{row.StartedAt, i, false})
	}
	for i, row := range fixture.Sockets {
		if selected[row.Connection] {
			steps = append(steps, step{row.StartedAt, i, true})
		}
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].at.Before(steps[j].at) })
	bindings := map[string]string{}
	sockets := map[string]*gatewayWSConn{}
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	frames := map[string]gatewayWSAuthorizerFrame{}
	durableReads := map[string]gatewaySDKObservation{}
	call := func(row gatewaySDKObservation) {
		t.Helper()
		input := gatewayClone(t, row.Input)
		gatewaySubstitute(input, bindings)
		if row.Operation == "CreateFunction" {
			input["Runtime"] = "python3.12"
			input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
		}
		capture := &gatewayWSManagementHTTP{client: clients.server.Client()}
		options := config()
		options.HTTPClient = capture
		client := gatewaySDKClient(t, row.Service, options)
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		out, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
		if capture.status != row.Result.HTTPStatus {
			t.Fatalf("%s HTTP=%d native=%d: %v", row.Label, capture.status, row.Result.HTTPStatus, err)
		}
		if row.Result.Code != "Success" {
			assertAPIError(t, err, row.Result.Code)
			return
		}
		if err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
		encoded, err = json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]any
		awsDecodeJSON(t, encoded, &actual)
		for _, key := range []string{"ApiId", "ApiEndpoint", "AuthorizerId", "IntegrationId", "RouteId", "RouteResponseId", "DeploymentId"} {
			if native, ok := row.Result.Output[key].(string); ok {
				gatewayWSAuthorizerBind(t, row.Label+" "+key, native, actual[key], bindings)
			}
		}
		gatewayWSAuthorizerControl(t, row.Label, actual, row.Result.Output, bindings)
		if row.Operation == "CreateFunction" {
			function := input["FunctionName"].(string)
			if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &function}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
				t.Fatalf("%s: %v", row.Label, err)
			}
		}
	}
	reopened := false
	controls, wireOperations := 0, 0
	for _, step := range steps {
		if step.at.After(source.Now()) {
			source.Advance(step.at.Sub(source.Now()))
		}
		if !step.socket {
			row := fixture.Observations[step.index]
			call(row)
			if len(fixture.Sockets) == 0 {
				clients = reopen()
			}
			if !reopened && row.Service == "apigatewayv2" && strings.HasPrefix(row.Operation, "Get") {
				key, err := json.Marshal(row.Input)
				if err != nil {
					t.Fatal(err)
				}
				durableReads[row.Operation+string(key)] = row
			}
			controls++
			continue
		}
		if !reopened {
			// Compare retained authorizer, route, stage and deployment controls
			// before opening sockets. Never restart the held live connection.
			clients = reopen()
			for _, row := range durableReads {
				call(row)
			}
			reopened = true
		}
		row := fixture.Sockets[step.index]
		socket := sockets[row.Connection]
		switch row.Operation {
		case "connect":
			origin, err := url.Parse(row.Request.URL)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := "ws" + strings.TrimPrefix(clients.server.URL, "http") + "/_stackd/execute-api/" + bindings[fixture.Owned.API] + origin.RequestURI()
			headers := make(http.Header)
			for _, header := range row.Request.Headers {
				headers.Add(header[0], header[1]) // Preserve duplicates and empty values.
			}
			headers.Set("Origin", row.Request.Origin)
			connection, status, responseHeaders, body, dialErr := gatewayWSDial(t.Context(), endpoint, headers)
			if connection != nil {
				sockets[row.Connection] = connection
			}
			if status != row.Result.Status || status == http.StatusSwitchingProtocols && dialErr != nil || status != http.StatusSwitchingProtocols && dialErr == nil {
				t.Fatalf("%s handshake=%d body=%s error=%v, native=%d", row.Label, status, body, dialErr, row.Result.Status)
			}
			if status != http.StatusSwitchingProtocols {
				gatewayWSAuthorizerRejection(t, row, responseHeaders, body, bindings)
			}
		case "send":
			if socket == nil {
				t.Fatalf("%s lost its retained socket", row.Label)
			}
			payload := []byte(row.Request.Text)
			if row.Request.Base64 != "" {
				payload = gatewayWSDecode64(t, row.Request.Base64)
			}
			if err := socket.Send(row.Request.Opcode, payload); err != nil {
				t.Fatalf("%s: %v", row.Label, err)
			}
		case "receive", "close":
			if socket == nil {
				t.Fatalf("%s lost its retained socket", row.Label)
			}
			if row.Operation == "close" {
				if err := socket.Send(ws.OpClose, ws.NewCloseFrameBody(ws.StatusCode(row.Request.CloseCode), row.Request.CloseReason)); err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
			}
			payload, opcode, err := socket.Read(time.Duration(row.Request.TimeoutSeconds * float64(time.Second)))
			if err != nil || opcode != row.Result.Opcode || row.Result.Outcome != "frame" {
				t.Fatalf("%s opcode=%d payload=%s error=%v, native=%+v", row.Label, opcode, payload, err, row.Result)
			}
			if row.Operation == "close" {
				if !bytes.Equal(payload, gatewayWSDecode64(t, row.Result.Base64)) {
					t.Fatalf("%s close payload=%q native=%q", row.Label, payload, gatewayWSDecode64(t, row.Result.Base64))
				}
				_ = socket.Close()
				delete(sockets, row.Connection)
			} else {
				marker, ok := receives[row.Label]
				if !ok {
					t.Fatalf("%s has no native scenario correlation", row.Label)
				}
				frames[marker] = gatewayWSAuthorizerFrame{actual: payload, native: []byte(row.Result.Text)}
			}
		default:
			t.Fatalf("unsupported native socket operation %s", row.Operation)
		}
		wireOperations++
	}
	var actual []gatewayWSAuthorizerRecord
	if fixture.Owned.LogGroup != "" {
		actual = gatewayWSAuthorizerLogs(t, gatewaySDKClient(t, "logs", config()).(*cloudwatchlogs.Client), fixture.Owned.LogGroup, len(expected))
	}
	gatewayWSAuthorizerCompareLogs(t, actual, expected, frames, bindings, configuredStages)
	sort.Strings(excluded)
	t.Logf("replayed %d native controls, %d socket operations, %d real Lambda records across %d selected connections; backend=%s, durable controls checked across reopen", controls, wireOperations, len(actual), len(selected), backend)
	t.Logf("excluded: %s; prior_captures[0] is transport-incomplete and not used; Python 3.13 handler replayed on pinned Python 3.12; no latency, readiness-convergence, or guaranteed disconnect-delivery claim", strings.Join(excluded, ", "))
}

func gatewayWSAuthorizerBind(t *testing.T, label, native string, actual any, bindings map[string]string) {
	t.Helper()
	value, ok := actual.(string)
	if !ok || native == "" || value == "" {
		t.Fatalf("%s missing generated identifier: native=%q actual=%v", label, native, actual)
	}
	if previous, exists := bindings[native]; exists && previous != value {
		t.Fatalf("%s changed identity %q from %q to %q", label, native, previous, value)
	}
	for old, bound := range bindings {
		if old != native && bound == value {
			t.Fatalf("%s reused identity %q for %q and %q", label, value, old, native)
		}
	}
	bindings[native] = value
}

func gatewayWSAuthorizerControl(t *testing.T, label string, actual, native map[string]any, bindings map[string]string) {
	t.Helper()
	want := gatewayClone(t, native)
	gatewaySubstitute(want, bindings)
	// Only these generated identifiers are bound above. All authorizer and
	// deployment semantics below are compared, including absent/empty fields.
	for _, key := range []string{"ApiId", "AuthorizerId", "IntegrationId", "RouteId", "RouteResponseId", "DeploymentId", "Name", "ProtocolType", "RouteSelectionExpression", "AuthorizerType", "AuthorizerUri", "AuthorizerCredentialsArn", "IdentitySource", "IdentityValidationExpression", "AuthorizerResultTtlInSeconds", "AuthorizerPayloadFormatVersion", "EnableSimpleResponses", "AuthorizationType", "RouteKey", "Target", "RouteResponseSelectionExpression", "RouteResponseKey", "IntegrationType", "IntegrationMethod", "IntegrationUri", "StageName", "StageVariables", "AutoDeploy", "AutoDeployed", "DeploymentStatus"} {
		if !reflect.DeepEqual(actual[key], want[key]) {
			t.Fatalf("%s %s=%v native=%v", label, key, actual[key], want[key])
		}
	}
	if items, ok := want["Items"].([]any); ok {
		got, _ := actual["Items"].([]any)
		if len(got) != len(items) {
			t.Fatalf("%s retained item count=%d native=%d", label, len(got), len(items))
		}
		for _, item := range items {
			object := item.(map[string]any)
			matched := false
			for _, candidate := range got {
				value := candidate.(map[string]any)
				if object["RouteId"] != nil && object["RouteId"] == value["RouteId"] || object["DeploymentId"] != nil && object["DeploymentId"] == value["DeploymentId"] {
					gatewayWSAuthorizerControl(t, label+" retained item", value, object, nil)
					matched = true
					break
				}
			}
			if !matched {
				t.Fatalf("%s missing retained resource %v", label, object)
			}
		}
	}
	if policy, ok := want["Policy"].(string); ok {
		var got, expected map[string]any
		awsDecodeJSON(t, []byte(actual["Policy"].(string)), &got)
		awsDecodeJSON(t, []byte(policy), &expected)
		if !reflect.DeepEqual(got["Statement"], expected["Statement"]) {
			t.Fatalf("%s Lambda resource policy=%v native=%v", label, got, expected)
		}
	}
	if role, ok := want["Role"].(map[string]any); ok {
		got := actual["Role"].(map[string]any)
		policy, err := url.QueryUnescape(got["AssumeRolePolicyDocument"].(string))
		if err != nil {
			t.Fatal(err)
		}
		var trust map[string]any
		awsDecodeJSON(t, []byte(policy), &trust)
		if got["Arn"] != role["Arn"] || !reflect.DeepEqual(trust, role["AssumeRolePolicyDocument"]) {
			t.Fatalf("%s role identity/trust=%v native=%v", label, got, role)
		}
	}
}

func gatewayWSAuthorizerRejection(t *testing.T, row gatewayWSAuthorizerSocket, headers http.Header, body []byte, bindings map[string]string) {
	t.Helper()
	if headers.Get("Content-Type") != row.Result.Headers["content-type"] || headers.Get("X-Amzn-ErrorType") != "" || headers.Get("X-Amzn-Requestid") != "" {
		t.Fatalf("%s non-native error headers: %v", row.Label, headers)
	}
	native := gatewayWSDecode64(t, row.Result.Body.Base64)
	if row.Result.Status == http.StatusBadRequest {
		if headers.Get("X-Amz-Apigw-Id") != "" {
			t.Fatalf("%s duplicate Authorization must remain an unmodeled HTTP400: headers=%v", row.Label, headers)
		}
		return
	}
	var got, want map[string]any
	awsDecodeJSON(t, body, &got)
	awsDecodeJSON(t, native, &want)
	// Error shape and empty malformed-response messages affect consumers;
	// AWS's diagnostic prose and HTML whitespace are not stable contracts.
	for _, message := range []map[string]any{got, want} {
		text, ok := message["message"].(string)
		if !ok {
			t.Fatalf("%s missing string error message: %v", row.Label, message)
		}
		message["message"] = text != ""
	}
	for _, key := range []string{"connectionId", "requestId"} {
		gatewayWSAuthorizerBind(t, row.Label+" "+key, want[key].(string), got[key], bindings)
	}
	if headers.Get("X-Amz-Apigw-Id") != got["requestId"] {
		t.Fatalf("%s gateway header does not correlate with error requestId: %v %v", row.Label, headers, got)
	}
	gatewaySubstitute(want, bindings)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s error JSON=%v native=%v", row.Label, got, want)
	}
}

func gatewayWSAuthorizerLogs(t *testing.T, client *cloudwatchlogs.Client, group string, count int) []gatewayWSAuthorizerRecord {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for {
		var records []gatewayWSAuthorizerRecord
		for _, message := range gatewayLogMessages(t, ctx, client, group, `"websocket-authorizer"`) {
			var record gatewayWSAuthorizerRecord
			if json.Unmarshal([]byte(strings.TrimSpace(message)), &record) == nil && record.ProbeKind == "websocket-authorizer" {
				records = append(records, record)
			}
		}
		if len(records) >= count {
			if len(records) != count {
				t.Fatalf("Lambda invoked %d times, native selected timeline requires %d (including rejected handshakes and no MESSAGE/DISCONNECT reauthorization)", len(records), count)
			}
			return records
		}
		select {
		case <-ctx.Done():
			t.Fatalf("only %d/%d expected real Lambda logs arrived: %+v", len(records), count, records)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func gatewayWSAuthorizerCompareLogs(t *testing.T, actual, expected []gatewayWSAuthorizerRecord, frames map[string]gatewayWSAuthorizerFrame, bindings map[string]string, configuredStages map[string]map[string]any) {
	t.Helper()
	matched := map[string]gatewayWSAuthorizerRecord{}
	used := map[string]bool{}
	// Establish identifiers from actual authorizer and CONNECT/MESSAGE logs
	// before looking up marker-less DISCONNECT records or retained context.
	for _, disconnect := range []bool{false, true} {
		for _, native := range expected {
			request := native.Event["requestContext"].(map[string]any)
			if (request["eventType"] == "DISCONNECT") != disconnect {
				continue
			}
			var candidates []gatewayWSAuthorizerRecord
			for _, got := range actual {
				context := got.Event["requestContext"].(map[string]any)
				if got.Kind != native.Kind || context["eventType"] != request["eventType"] || !reflect.DeepEqual(got.Marker, native.Marker) {
					continue
				}
				if !disconnect || context["connectionId"] == bindings[request["connectionId"].(string)] {
					candidates = append(candidates, got)
				}
			}
			if len(candidates) != 1 {
				t.Fatalf("native %s/%s marker=%v has %d actual invocations, want exactly one", native.Kind, request["eventType"], native.Marker, len(candidates))
			}
			got := candidates[0]
			if used[got.Invocation] {
				t.Fatalf("reused Lambda invocation %s: no WebSocket identity cache is permitted", got.Invocation)
			}
			used[got.Invocation] = true
			gatewayWSAuthorizerBind(t, native.Kind+" invocation", native.Invocation, got.Invocation, bindings)
			context := got.Event["requestContext"].(map[string]any)
			for _, key := range []string{"connectionId", "requestId", "extendedRequestId", "messageId"} {
				if id, ok := request[key].(string); ok {
					gatewayWSAuthorizerBind(t, native.Kind+" "+key, id, context[key], bindings)
				}
			}
			matched[native.Invocation] = got
		}
	}
	connectedAt := map[string]any{}
	contexts := map[string]map[string]any{}
	authorizers, integrations := 0, 0
	for _, native := range expected {
		got := matched[native.Invocation]
		label := native.Kind + " " + native.Invocation
		if got.ProbeKind != native.ProbeKind || got.Kind != native.Kind || got.Mode != native.Mode || !reflect.DeepEqual(got.Raises, native.Raises) {
			t.Fatalf("%s log shape differs: got=%+v native=%+v", label, got, native)
		}
		event := native.Event
		if stage, changed := configuredStages[native.Invocation]; changed {
			event = gatewayClone(t, event)
			event["stageVariables"] = stage
		}
		gatewayWSAuthorizerEvent(t, label, got.Event, event, bindings, connectedAt)
		wantResponse := gatewayClone(t, native.Response)
		gatewaySubstitute(wantResponse, bindings)
		if got.Kind == "authorizer" {
			authorizers++
			if !reflect.DeepEqual(got.Response, wantResponse) {
				t.Fatalf("%s Lambda authorizer response=%v native=%v", label, got.Response, wantResponse)
			}
			continue
		}
		integrations++
		request := got.Event["requestContext"].(map[string]any)
		connection := request["connectionId"].(string)
		authorizer := gatewayClone(t, request["authorizer"].(map[string]any))
		if request["eventType"] == "CONNECT" {
			if latency, ok := authorizer["integrationLatency"].(float64); !ok || latency < 0 {
				t.Fatalf("%s missing numeric CONNECT integrationLatency: %v", label, authorizer)
			}
			delete(authorizer, "integrationLatency")
			contexts[connection] = authorizer
		} else if !reflect.DeepEqual(authorizer, contexts[connection]) {
			t.Fatalf("%s did not retain original authorizer context: %v originally=%v", label, authorizer, contexts[connection])
		}
		for _, record := range []gatewayWSAuthorizerRecord{got, native} {
			var body map[string]any
			awsDecodeJSON(t, []byte(record.Response["body"].(string)), &body)
			if !reflect.DeepEqual(body, map[string]any{"marker": record.Marker, "lambdaRequestId": record.Invocation, "event": record.Event}) {
				t.Fatalf("%s integration response not correlated with its logged event: %v", label, body)
			}
		}
		response := gatewayClone(t, got.Response)
		delete(response, "body")
		delete(wantResponse, "body")
		if !reflect.DeepEqual(response, wantResponse) {
			t.Fatalf("%s integration response=%v native=%v", label, response, wantResponse)
		}
		if request["eventType"] == "MESSAGE" {
			marker := got.Marker.(string)
			frame := frames[marker]
			if !bytes.Equal(frame.actual, []byte(got.Response["body"].(string))) || !bytes.Equal(frame.native, []byte(native.Response["body"].(string))) {
				t.Fatalf("%s frame is not its correlated Lambda response: actual=%s native=%s", marker, frame.actual, frame.native)
			}
			delete(frames, marker)
		}
	}
	if len(used) != len(actual) || len(frames) != 0 {
		t.Fatalf("uncorrelated actual invocations/frames: used=%d actual=%d frames=%v", len(used), len(actual), frames)
	}
	t.Logf("correlated exactly %d REQUEST authorizer and %d integration invocations; each retained MESSAGE/DISCONNECT preserves its original authorization", authorizers, integrations)
}

func gatewayWSAuthorizerEvent(t *testing.T, label string, actual, native map[string]any, bindings map[string]string, connectedAt map[string]any) {
	t.Helper()
	request := actual["requestContext"].(map[string]any)
	connection := request["connectionId"].(string)
	if previous, ok := connectedAt[connection]; ok && previous != request["connectedAt"] {
		t.Fatalf("%s changed original connectedAt: %v previously=%v", label, request, previous)
	}
	connectedAt[connection] = request["connectedAt"]
	epoch, epochOK := request["requestTimeEpoch"].(float64)
	connected, connectedOK := request["connectedAt"].(float64)
	stamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", request["requestTime"].(string))
	if !epochOK || !connectedOK || connected <= 0 || epoch < connected || err != nil || stamp.Unix() != int64(epoch)/1000 || request["requestId"] != request["extendedRequestId"] {
		t.Fatalf("%s inconsistent event time/request identity: %v", label, request)
	}
	got, want := gatewayClone(t, actual), gatewayClone(t, native)
	gatewaySubstitute(want, bindings)
	for _, event := range []map[string]any{got, want} {
		context := event["requestContext"].(map[string]any)
		for _, key := range []string{"requestTime", "domainName"} {
			gatewayWSNormalizeLifecycleValue(t, label, context, key)
		}
		for _, key := range []string{"connectedAt", "requestTimeEpoch"} {
			if value, ok := context[key].(float64); !ok || value <= 0 {
				t.Fatalf("%s invalid native/local %s: %v", label, key, context[key])
			}
			context[key] = float64(1)
		}
		identity := context["identity"].(map[string]any)
		if ip, ok := identity["sourceIp"].(string); !ok || net.ParseIP(ip) == nil {
			t.Fatalf("%s invalid source IP: %v", label, identity)
		}
		gatewayWSNormalizeLifecycleValue(t, label, identity, "sourceIp")
		if authorizer, ok := context["authorizer"].(map[string]any); ok {
			if latency, present := authorizer["integrationLatency"]; present {
				if number, ok := latency.(float64); !ok || number < 0 || context["eventType"] != "CONNECT" {
					t.Fatalf("%s invalid authorizer latency projection: %v", label, authorizer)
				}
				authorizer["integrationLatency"] = float64(0)
			}
		}
		for _, field := range []string{"headers", "multiValueHeaders"} {
			if headers, ok := event[field].(map[string]any); ok {
				for _, key := range []string{"Host", "Sec-WebSocket-Key", "X-Amzn-Trace-Id", "X-Forwarded-For", "X-Forwarded-Port", "X-Forwarded-Proto"} {
					gatewayWSNormalizeLifecycleValue(t, label, headers, key)
				}
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Fatalf("%s customer event differs\ngot  %s\nwant %s", label, gotJSON, wantJSON)
	}
}
