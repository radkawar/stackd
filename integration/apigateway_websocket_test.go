package stackd_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

type gatewayWSLifecycleFixture struct {
	Account, Region string
	HandlerSource   string `json:"handler_source"`
	Owned           struct {
		API      string `json:"http_api"`
		LogGroup string `json:"log_group"`
	}
	Observations []gatewaySDKObservation
	Sockets      []gatewayWSLifecycleSocket `json:"websocket_observations"`
	Scenarios    []struct {
		Label, Marker, Connection, Phase string
		SendLabel                        string   `json:"send_label"`
		ReceiveLabel                     string   `json:"receive_label"`
		Outcome                          string   `json:"receive_outcome"`
		LogIDs                           []string `json:"lambda_log_event_ids"`
		Correlated                       bool     `json:"frame_invocation_matches_log"`
	}
	Readiness []struct {
		Connection string
		Ready      bool
	}
	Connections map[string]struct {
		ConnectLogIDs    []string `json:"connect_log_event_ids"`
		DisconnectLogIDs []string `json:"disconnect_log_event_ids"`
	}
	Logs []struct {
		ID     string `json:"event_id"`
		Record gatewayWSLifecycleRecord
	} `json:"invocation_logs"`
}

type gatewayWSLifecycleSocket struct {
	Label, Operation, Connection string
	StartedAt                    time.Time `json:"started_at"`
	Request                      struct {
		URL, Text, Base64 string
		Headers           map[string]string
		Opcode            ws.OpCode
		TimeoutSeconds    float64 `json:"timeout_seconds"`
		CloseCode         int     `json:"close_code"`
		CloseReason       string  `json:"close_reason"`
	}
	Result struct {
		Status                int
		Outcome, Text, Base64 string
		Opcode                ws.OpCode
		CloseCode             int `json:"close_code"`
		JSON                  map[string]any
		Body                  struct{ Base64 string }
	}
}

type gatewayWSLifecycleRecord struct {
	Kind       string `json:"probe_kind"`
	Marker     any
	Invocation string
	Event      map[string]any
	Response   map[string]any
}

func TestAPIGatewayNativeWebSocketLifecycle(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real WebSocket Lambda runtimes")
	}
	var fixture gatewayWSLifecycleFixture
	awsReadFixture(t, "apigateway/websocket_lifecycle.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) { gatewayReplayWSLifecycle(t, backend, fixture) })
	}
}

func gatewayReplayWSLifecycle(t *testing.T, backend string, fixture gatewayWSLifecycleFixture) {
	source := clock.NewManual(fixture.Observations[0].StartedAt)
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	config := func() aws.Config {
		return aws.Config{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1}
	}
	bindings := map[string]string{}
	logs := map[string]gatewayWSLifecycleRecord{}
	for _, row := range fixture.Logs {
		logs[row.ID] = row.Record
	}
	var twoWayDeployment time.Time
	for _, row := range fixture.Observations {
		if row.Operation == "UpdateStage" && row.Label == "d2-two-way-stage" {
			twoWayDeployment = row.StartedAt
		}
	}
	if twoWayDeployment.IsZero() {
		t.Fatal("fixture has no two-way deployment boundary")
	}
	socketRows := map[string]gatewayWSLifecycleSocket{}
	for _, row := range fixture.Sockets {
		socketRows[row.Label] = row
	}
	// Readiness success is not regional convergence. Keep only the final
	// successful samples on the sockets the native probe itself retained.
	retained := map[string]bool{}
	for _, row := range fixture.Readiness {
		if row.Ready {
			retained[row.Connection] = true
		}
	}
	selected := map[string]bool{}
	connections := map[string]bool{}
	messageLogs := map[string]gatewayWSLifecycleRecord{}
	var excluded []string
	for _, scenario := range fixture.Scenarios {
		if scenario.Phase == "readiness" && (!retained[scenario.Connection] || !scenario.Correlated) {
			excluded = append(excluded, scenario.Label)
			continue
		}
		if scenario.Outcome == "timeout" && socketRows[scenario.SendLabel].StartedAt.After(twoWayDeployment) {
			// Native d2-original-default and d2-fresh-custom are late
			// propagation samples, not evidence of deterministic silence.
			excluded = append(excluded, scenario.Label)
			continue
		}
		if len(scenario.LogIDs) != 1 {
			t.Fatalf("%s must have one correlated native invocation, got %v", scenario.Label, scenario.LogIDs)
		}
		record, ok := logs[scenario.LogIDs[0]]
		if !ok || record.Marker != scenario.Marker {
			t.Fatalf("%s has no native invocation evidence", scenario.Label)
		}
		selected[scenario.SendLabel], selected[scenario.ReceiveLabel] = true, true
		messageLogs[scenario.ReceiveLabel] = record
		connections[scenario.Connection] = true
	}
	for _, row := range fixture.Sockets {
		if row.Result.CloseCode == 1003 || row.Operation == "connect" && row.Result.Status == http.StatusForbidden {
			connections[row.Connection] = true
		}
	}
	for _, row := range fixture.Sockets {
		if connections[row.Connection] && (row.Operation == "connect" || row.Operation == "close" || strings.HasPrefix(row.Label, "binary-input-")) {
			selected[row.Label] = true
		}
	}
	type step struct {
		at     time.Time
		index  int
		socket bool
	}
	var steps []step
	for i, row := range fixture.Observations {
		if strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "absence-") || row.Service == "logs" && row.Operation != "CreateLogGroup" || row.Operation == "GetFunctionConfiguration" || row.Operation == "CreateFunction" && row.Result.Code != "Success" {
			continue
		}
		steps = append(steps, step{row.StartedAt, i, false})
	}
	for i, row := range fixture.Sockets {
		if selected[row.Label] {
			steps = append(steps, step{row.StartedAt, i, true})
		}
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].at.Before(steps[j].at) })
	sockets := map[string]*gatewayWSConn{}
	t.Cleanup(func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	})
	connectedAt := map[string]any{}
	reopened := false
	controls, wireOperations, records, oneWay := 0, 0, 0, 0
	checkLog := func(label string, native gatewayWSLifecycleRecord) gatewayWSLifecycleRecord {
		t.Helper()
		client := gatewaySDKClient(t, "logs", config()).(*cloudwatchlogs.Client)
		actual := gatewayWSLifecycleLog(t, client, fixture.Owned.LogGroup, native, bindings)
		gatewayWSCompareLifecycleRecord(t, label, actual, native, bindings, connectedAt)
		records++
		return actual
	}
	for _, step := range steps {
		if step.at.After(source.Now()) {
			source.Advance(step.at.Sub(source.Now()))
		}
		if !step.socket {
			row := fixture.Observations[step.index]
			input := gatewayClone(t, row.Input)
			gatewaySubstitute(input, bindings)
			if row.Operation == "CreateFunction" {
				input["Runtime"] = "python3.12"
				input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
			}
			client := gatewaySDKClient(t, row.Service, config())
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			output, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
			if err != nil {
				t.Fatalf("%s: %v", row.Label, err)
			}
			encoded, err = json.Marshal(output)
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]any
			awsDecodeJSON(t, encoded, &actual)
			// Bind identifiers only: a route-key regression must not turn
			// into a substitution that makes its Lambda event look native.
			for _, key := range []string{"ApiId", "ApiEndpoint", "IntegrationId", "RouteId", "RouteResponseId", "DeploymentId"} {
				if expected, ok := row.Result.Output[key].(string); ok {
					value, ok := actual[key].(string)
					if !ok || value == "" {
						t.Fatalf("%s missing generated %s: %v", row.Label, key, actual)
					}
					if previous, bound := bindings[expected]; bound && previous != value {
						t.Fatalf("%s changed bound %s: %s -> %s", row.Label, key, previous, value)
					}
					gatewayBind(map[string]any{key: expected}, map[string]any{key: value}, bindings)
				}
			}
			for _, key := range []string{"ProtocolType", "RouteSelectionExpression", "IntegrationType", "IntegrationMethod", "IntegrationUri", "RouteKey", "Target", "RouteResponseSelectionExpression", "RouteResponseKey", "StageName", "AutoDeploy"} {
				if expected, ok := row.Result.Output[key]; ok {
					if text, ok := expected.(string); ok {
						expected = gatewayReplace(text, bindings)
					}
					if !reflect.DeepEqual(actual[key], expected) {
						t.Fatalf("%s %s=%v, native=%v", row.Label, key, actual[key], expected)
					}
				}
			}
			if row.Operation == "CreateFunction" {
				name := input["FunctionName"].(string)
				if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
			}
			controls++
			continue
		}
		// Reconstruct the retained deployment before the first socket, never
		// across the old sockets whose continued behavior is under test.
		if !reopened {
			clients = reopen()
			reopened = true
		}
		row := fixture.Sockets[step.index]
		socket := sockets[row.Connection]
		switch row.Operation {
		case "connect":
			evidence := fixture.Connections[row.Connection].ConnectLogIDs
			if len(evidence) != 1 {
				t.Fatalf("%s has no unique native connect record", row.Label)
			}
			native := logs[evidence[0]]
			origin, err := url.Parse(row.Request.URL)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := "ws" + strings.TrimPrefix(clients.server.URL, "http") + "/_stackd/execute-api/" + bindings[fixture.Owned.API] + origin.RequestURI()
			headers := make(http.Header)
			for key, value := range row.Request.Headers {
				headers.Set(key, value)
			}
			// The native probe supplies Origin at the transport layer.
			if value, ok := native.Event["headers"].(map[string]any)["Origin"].(string); ok {
				headers.Set("Origin", value)
			}
			connection, status, _, body, dialErr := gatewayWSDial(t.Context(), endpoint, headers)
			if connection != nil {
				sockets[row.Connection] = connection
			}
			if status != row.Result.Status || status == http.StatusSwitchingProtocols && dialErr != nil || status != http.StatusSwitchingProtocols && dialErr == nil {
				t.Fatalf("%s: handshake=%d body=%s error=%v, native=%d", row.Label, status, body, dialErr, row.Result.Status)
			}
			actual := checkLog(row.Label, native)
			if status != http.StatusSwitchingProtocols {
				gatewayWSLifecycleBody(t, row.Label, body, gatewayWSDecode64(t, row.Result.Body.Base64), bindings)
				if string(body) != actual.Response["body"] {
					t.Fatalf("%s rejected body differs from the actual Lambda response", row.Label)
				}
			}
		case "send":
			if socket == nil {
				t.Fatalf("%s has no retained socket", row.Label)
			}
			payload := []byte(row.Request.Text)
			if row.Request.Base64 != "" {
				payload = gatewayWSDecode64(t, row.Request.Base64)
			}
			if err := socket.Send(row.Request.Opcode, payload); err != nil {
				t.Fatalf("%s: %v", row.Label, err)
			}
		case "receive":
			if native, ok := messageLogs[row.Label]; ok {
				// Logs prove the one-way integration ran, rather than merely
				// mistaking failed delivery for correct absence of a frame.
				actual := checkLog(row.Label, native)
				payload, opcode, err := socket.Read(time.Duration(row.Request.TimeoutSeconds * float64(time.Second)))
				if row.Result.Outcome == "timeout" {
					var timeout net.Error
					if len(payload) != 0 || opcode != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
						t.Fatalf("%s: expected bounded one-way silence, opcode=%d payload=%s error=%v", row.Label, opcode, payload, err)
					}
					oneWay++
				} else {
					if err != nil || opcode != row.Result.Opcode {
						t.Fatalf("%s: opcode=%d error=%v, native opcode=%d", row.Label, opcode, err, row.Result.Opcode)
					}
					gatewayWSLifecycleBody(t, row.Label, payload, []byte(row.Result.Text), bindings)
					if string(payload) != actual.Response["body"] {
						t.Fatalf("%s frame is not the correlated Lambda response: %s", row.Label, payload)
					}
				}
			} else {
				payload, opcode, err := socket.Read(time.Duration(row.Request.TimeoutSeconds * float64(time.Second)))
				if err != nil || opcode != row.Result.Opcode || !bytes.Equal(payload, gatewayWSDecode64(t, row.Result.Base64)) {
					t.Fatalf("%s: opcode=%d payload=%q error=%v, native=%+v", row.Label, opcode, payload, err, row.Result)
				}
			}
		case "close":
			if row.Result.Outcome != "already_closed" {
				if err := socket.Send(ws.OpClose, ws.NewCloseFrameBody(ws.StatusCode(row.Request.CloseCode), row.Request.CloseReason)); err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
				payload, opcode, err := socket.Read(time.Duration(row.Request.TimeoutSeconds * float64(time.Second)))
				if err != nil || opcode != row.Result.Opcode || !bytes.Equal(payload, gatewayWSDecode64(t, row.Result.Base64)) {
					t.Fatalf("%s: close opcode=%d payload=%q error=%v", row.Label, opcode, payload, err)
				}
			}
			_ = socket.Close()
			delete(sockets, row.Connection)
			for _, id := range fixture.Connections[row.Connection].DisconnectLogIDs {
				checkLog(row.Label, logs[id])
			}
		default:
			t.Fatalf("unsupported socket operation %s", row.Operation)
		}
		wireOperations++
	}
	t.Logf("replayed %d SDK controls, %d socket operations, %d real Lambda log records (%d one-way invocations); backend=%s reopened before first socket", controls, wireOperations, records, oneWay, backend)
	t.Logf("excluded nondeterministic native propagation/readiness samples: %s; runtime Python 3.13 capture replayed on pinned Python 3.12; no latency, permanent-silence, global-convergence, or guaranteed-disconnect-delivery claim", strings.Join(excluded, ", "))
}

func gatewayWSDecode64(t *testing.T, encoded string) []byte {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func gatewayWSLifecycleBody(t *testing.T, label string, actual, native []byte, bindings map[string]string) {
	t.Helper()
	var got, want map[string]any
	awsDecodeJSON(t, actual, &got)
	awsDecodeJSON(t, native, &want)
	gatewaySubstitute(want, bindings)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s body=%s, native=%v", label, actual, want)
	}
}

func gatewayWSLifecycleLog(t *testing.T, client *cloudwatchlogs.Client, group string, native gatewayWSLifecycleRecord, bindings map[string]string) gatewayWSLifecycleRecord {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	wantContext := native.Event["requestContext"].(map[string]any)
	var messages []string
	for {
		messages = gatewayLogMessages(t, ctx, client, group, `"websocket-lifecycle"`)
		for _, message := range messages {
			var record gatewayWSLifecycleRecord
			if json.Unmarshal([]byte(message), &record) != nil || record.Kind != native.Kind {
				continue
			}
			request, ok := record.Event["requestContext"].(map[string]any)
			if !ok || request["eventType"] != wantContext["eventType"] {
				continue
			}
			if native.Marker != nil && record.Marker == native.Marker || native.Marker == nil && request["connectionId"] == gatewayReplace(wantContext["connectionId"].(string), bindings) {
				return record
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no real Lambda log for marker=%v event=%v connection=%v: %v", native.Marker, wantContext["eventType"], wantContext["connectionId"], messages)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func gatewayWSCompareLifecycleRecord(t *testing.T, label string, actual, native gatewayWSLifecycleRecord, bindings map[string]string, connectedAt map[string]any) {
	t.Helper()
	gotContext, ok := actual.Event["requestContext"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no customer requestContext: %v", label, actual.Event)
	}
	wantContext := native.Event["requestContext"].(map[string]any)
	connection, ok := gotContext["connectionId"].(string)
	if !ok || connection == "" || actual.Invocation == "" {
		t.Fatalf("%s missing generated connection/invocation identity", label)
	}
	nativeConnection := wantContext["connectionId"].(string)
	if wantContext["eventType"] == "CONNECT" {
		bindings[nativeConnection] = connection
		connectedAt[connection] = gotContext["connectedAt"]
	} else if bindings[nativeConnection] != connection || !reflect.DeepEqual(connectedAt[connection], gotContext["connectedAt"]) {
		t.Fatalf("%s did not retain its connection identity/time: %v", label, gotContext)
	}
	bindings[native.Invocation] = actual.Invocation
	if actual.Kind != native.Kind || !reflect.DeepEqual(actual.Marker, native.Marker) {
		t.Fatalf("%s log correlation mismatch: %+v", label, actual)
	}
	epoch, epochOK := gotContext["requestTimeEpoch"].(float64)
	connected, connectedOK := gotContext["connectedAt"].(float64)
	if !epochOK || !connectedOK || connected <= 0 || epoch < connected || gotContext["requestTime"] != time.UnixMilli(int64(epoch)).UTC().Format("02/Jan/2006:15:04:05 -0700") || gotContext["requestId"] != gotContext["extendedRequestId"] {
		t.Fatalf("%s inconsistent request time/identity: %v", label, gotContext)
	}
	got, want := gatewayClone(t, actual.Event), gatewayClone(t, native.Event)
	gatewaySubstitute(want, bindings)
	for _, event := range []map[string]any{got, want} {
		request := event["requestContext"].(map[string]any)
		// Retain every key and container. Only environment-generated values
		// change; absent/null/empty values cannot become present values.
		for _, key := range []string{"requestId", "extendedRequestId", "messageId", "requestTime", "domainName"} {
			gatewayWSNormalizeLifecycleValue(t, label, request, key)
		}
		for _, key := range []string{"connectedAt", "requestTimeEpoch"} {
			if value, exists := request[key]; exists {
				if number, ok := value.(float64); !ok || number <= 0 {
					t.Fatalf("%s invalid generated timestamp %s=%v", label, key, value)
				}
				request[key] = float64(1)
			}
		}
		if identity, ok := request["identity"].(map[string]any); ok {
			if ip, ok := identity["sourceIp"].(string); !ok || net.ParseIP(ip) == nil {
				t.Fatalf("%s invalid customer source IP: %v", label, identity)
			}
			gatewayWSNormalizeLifecycleValue(t, label, identity, "sourceIp")
		}
		for _, field := range []string{"headers", "multiValueHeaders"} {
			if headers, ok := event[field].(map[string]any); ok {
				for key := range headers {
					switch strings.ToLower(key) {
					case "host", "sec-websocket-key", "x-amzn-trace-id", "x-forwarded-for", "x-forwarded-port", "x-forwarded-proto":
						gatewayWSNormalizeLifecycleValue(t, label, headers, key)
					}
				}
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Fatalf("%s customer event differs\ngot  %s\nwant %s", label, gotJSON, wantJSON)
	}
	gotResponse, wantResponse := gatewayClone(t, actual.Response), gatewayClone(t, native.Response)
	gotBody, gotOK := gotResponse["body"].(string)
	wantBody, wantOK := wantResponse["body"].(string)
	if !gotOK || !wantOK {
		t.Fatalf("%s missing Lambda response body", label)
	}
	gatewayWSLifecycleBody(t, label+" Lambda", []byte(gotBody), []byte(wantBody), bindings)
	gotResponse["body"], wantResponse["body"] = "<compared-json-body>", "<compared-json-body>"
	if !reflect.DeepEqual(gotResponse, wantResponse) {
		t.Fatalf("%s Lambda response=%v, native=%v", label, gotResponse, wantResponse)
	}
}

func gatewayWSNormalizeLifecycleValue(t *testing.T, label string, object map[string]any, key string) {
	t.Helper()
	value, present := object[key]
	if !present {
		return
	}
	switch value := value.(type) {
	case string:
		if value != "" {
			object[key] = "<generated:" + strings.ToLower(key) + ">"
		}
	case []any:
		for i, element := range value {
			text, ok := element.(string)
			if !ok {
				t.Fatalf("%s invalid generated header %s=%v", label, key, value)
			}
			if text != "" {
				value[i] = "<generated:" + strings.ToLower(key) + ">"
			}
		}
	default:
		t.Fatalf("%s invalid generated field %s=%v", label, key, value)
	}
}
