package stackd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gobwas/ws"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type gatewayV2CredentialsFixture struct {
	gatewayTimelineFixture
	Owned struct{ Function string }
	APIs  map[string]struct {
		ID           string
		Integrations map[string]string
	}
	Scenarios    []gatewayV2CredentialsScenario
	Sockets      []gatewayWSLifecycleSocket                    `json:"websocket_observations"`
	Logs         []struct{ Record gatewayV2CredentialsRecord } `json:"invocation_logs"`
	TrustContext *gatewayV2CredentialsFixture                  `json:"trust_context_capture"`
}

type gatewayV2CredentialsScenario struct {
	Label, Protocol, Surface, Phase, Marker, Connection string
	BackendSuccess                                      bool     `json:"backend_success"`
	Invocations                                         int      `json:"observed_backend_invocations"`
	InvocationIDs                                       []string `json:"invocation_ids"`
}

type gatewayV2CredentialsRecord struct {
	Kind       string `json:"probe_kind"`
	Marker     string
	Invocation string `json:"invocation_id"`
	Event      map[string]any
}

func TestAPIGatewayNativeV2IntegrationCredentials(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real integration credential runtimes")
	}
	var fixture gatewayV2CredentialsFixture
	awsReadFixture(t, "apigateway/v2_integration_credentials.json", &fixture)
	for _, capture := range []struct {
		name    string
		fixture *gatewayV2CredentialsFixture
	}{
		{"timeline", &fixture},
		{"trust_context", fixture.TrustContext},
	} {
		if capture.fixture == nil {
			t.Fatalf("missing native %s capture", capture.name)
		}
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(capture.name+"/"+backend, func(t *testing.T) {
				gatewayReplayV2Credentials(t, backend, *capture.fixture)
			})
		}
	}
}

func gatewayReplayV2Credentials(t *testing.T, backend string, fixture gatewayV2CredentialsFixture) {
	source := clock.NewManual(fixture.Observations[0].StartedAt)
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	config := func(creds credentials.StaticCredentialsProvider) aws.Config {
		return aws.Config{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: creds, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1}
	}
	// The probe's IAM user is also the principal in the scoped actor's trust.
	owner := gatewayNativeUser(t, clients, fixture.Account, fixture.Region, fixture.Identity.Arn)
	actors := map[string]credentials.StaticCredentialsProvider{fixture.Identity.Arn: owner}
	bindings := map[string]string{}

	// A final sample from each readiness group is bounded native evidence, not
	// a promise about AWS propagation delay. In particular these retain the
	// deployed removal failure and replacement restoration on the held socket.
	selected := map[string]gatewayV2CredentialsScenario{}
	lastReadiness := map[string]gatewayV2CredentialsScenario{}
	for _, scenario := range fixture.Scenarios {
		if scenario.Phase == "semantic" {
			selected[scenario.Label] = scenario
			continue
		}
		if scenario.Phase != "readiness" {
			t.Fatalf("unclassified native scenario %+v", scenario)
		}
		cut := strings.LastIndexByte(scenario.Label, '-')
		if cut < 0 {
			t.Fatalf("readiness scenario lacks sample index: %s", scenario.Label)
		}
		if _, err := strconv.Atoi(scenario.Label[cut+1:]); err != nil {
			t.Fatalf("readiness scenario lacks sample index: %s", scenario.Label)
		}
		lastReadiness[scenario.Label[:cut]] = scenario
	}
	for _, scenario := range lastReadiness {
		selected[scenario.Label] = scenario
	}
	wireScenarios := map[string]gatewayV2CredentialsScenario{}
	selectedConnections := map[string]bool{}
	markers := map[string]gatewayV2CredentialsScenario{}
	for _, scenario := range selected {
		markers[scenario.Marker] = scenario
		switch scenario.Surface {
		case "request":
			wireScenarios[scenario.Label] = scenario
		case "connect":
			wireScenarios[scenario.Label+"-connect"] = scenario
			selectedConnections[scenario.Label] = true
		case "held-message":
			wireScenarios[scenario.Label+"-send"] = scenario
			wireScenarios[scenario.Label+"-receive"] = scenario
		default:
			t.Fatalf("unhandled native surface %s", scenario.Surface)
		}
	}
	type step struct {
		at    time.Time
		kind  string
		index int
	}
	var steps []step
	var excluded []string
	for i, row := range fixture.Observations {
		switch {
		case strings.HasPrefix(row.Label, "cleanup-"), strings.HasPrefix(row.Label, "absence-"), row.Service == "logs" && row.Operation != "CreateLogGroup":
			continue
		case row.Operation == "GetFunctionConfiguration", row.Operation == "CreateFunction" && row.Result.Code != "Success", row.Phase == "readiness" && row.Result.Code != "Success" && row.Operation != "GetPolicy":
			excluded = append(excluded, row.Label+" (readiness/propagation)")
			continue
		case row.Phase == "authority-propagation":
			// These bounded samples diagnose API policy propagation, not
			// PassRole. Owner GETs still verify the rejected updates' state.
			excluded = append(excluded, row.Label+" (independent API policy propagation)")
			continue
		}
		steps = append(steps, step{row.StartedAt, "control", i})
	}
	for i, row := range fixture.HTTP {
		if _, ok := wireScenarios[row.Label]; ok {
			steps = append(steps, step{row.StartedAt, "http", i})
		}
	}
	for i, row := range fixture.Sockets {
		if _, ok := wireScenarios[row.Label]; ok || row.Operation == "close" && selectedConnections[row.Connection] {
			steps = append(steps, step{row.StartedAt, "socket", i})
		}
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].at.Before(steps[j].at) })
	retainedIntegrations := map[string]bool{}
	for _, api := range fixture.APIs {
		for _, id := range api.Integrations {
			retainedIntegrations[id] = true
		}
	}
	durableReads := map[string]gatewaySDKObservation{}
	call := func(row gatewaySDKObservation) {
		t.Helper()
		input := gatewayClone(t, row.Input)
		gatewaySubstitute(input, bindings)
		if row.Operation == "CreateFunction" {
			input["Runtime"] = "python3.12"
			input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
		}
		creds, ok := actors[row.Actor.Arn]
		if !ok {
			t.Fatalf("%s has no established actor %s", row.Label, row.Actor.Arn)
		}
		capture := &awstest.WireClient{Client: clients.server.Client()}
		options := config(creds)
		options.HTTPClient = capture
		client := gatewaySDKClient(t, row.Service, options)
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		out, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
		if capture.Status != row.Result.HTTPStatus {
			t.Fatalf("%s HTTP=%d native=%d: %v", row.Label, capture.Status, row.Result.HTTPStatus, err)
		}
		if row.Result.Code != "Success" {
			assertAPIError(t, err, row.Result.Code)
			if row.Service == "apigatewayv2" && row.Result.Code == "AccessDeniedException" && (row.Operation == "CreateIntegration" || row.Operation == "UpdateIntegration") && !strings.Contains(err.Error(), "iam:PassRole") {
				t.Fatalf("%s did not reject the native iam:PassRole authority: %v", row.Label, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
		if session, ok := out.(*sts.AssumeRoleOutput); ok {
			nativeActor := row.Result.Output["AssumedRoleUser"].(map[string]any)["Arn"].(string)
			actors[nativeActor] = credentials.NewStaticCredentialsProvider(*session.Credentials.AccessKeyId, *session.Credentials.SecretAccessKey, *session.Credentials.SessionToken)
		}
		encoded, err = json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]any
		awsDecodeJSON(t, encoded, &actual)
		for _, field := range []string{"ApiId", "ApiEndpoint", "IntegrationId", "RouteId", "RouteResponseId", "DeploymentId"} {
			if native, ok := row.Result.Output[field].(string); ok {
				gatewayWSAuthorizerBind(t, row.Label+" "+field, native, actual[field], bindings)
			}
		}
		gatewayWSAuthorizerControl(t, row.Label, actual, row.Result.Output, bindings)
		if row.Operation == "CreateIntegration" || row.Operation == "UpdateIntegration" || row.Operation == "GetIntegration" {
			var wire map[string]any
			awsDecodeJSON(t, capture.Body, &wire)
			want, present := row.Result.Output["CredentialsArn"]
			got, exists := wire["credentialsArn"]
			if present != exists || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(actual["CredentialsArn"], want) {
				t.Fatalf("%s credentials presence/value: wire=%v SDK=%v native=%v", row.Label, wire, actual["CredentialsArn"], row.Result.Output)
			}
		}
		if row.Operation == "CreateFunction" {
			function := input["FunctionName"].(string)
			if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &function}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
				t.Fatalf("%s: %v", row.Label, err)
			}
		}
	}
	sockets := map[string]*gatewayWSConn{}
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	observed := map[string]bool{}
	reopened := false
	controls, wireCalls := 0, 0
	for _, step := range steps {
		if step.at.After(source.Now()) {
			source.Advance(step.at.Sub(source.Now()))
		}
		if step.kind == "control" {
			row := fixture.Observations[step.index]
			call(row)
			if row.Result.Code == "Success" {
				id, _ := row.Input["IntegrationId"].(string)
				if row.Operation == "GetIntegration" && retainedIntegrations[id] || row.Operation == "GetStage" || row.Operation == "GetDeployment" {
					encoded, _ := json.Marshal(row.Input)
					durableReads[row.Operation+string(encoded)] = row
				}
			}
			controls++
			continue
		}
		if !reopened {
			// Both protocols execute from reopened deployment snapshots. Never
			// reopen while the native timeline requires a held live connection.
			clients = reopen()
			for _, row := range durableReads {
				call(row)
			}
			reopened = true
		}
		if step.kind == "http" {
			row := fixture.HTTP[step.index]
			scenario := wireScenarios[row.Label]
			endpoint := clients.server.URL + "/_stackd/execute-api/" + bindings[fixture.APIs["HTTP"].ID] + row.Path
			request, err := http.NewRequestWithContext(t.Context(), row.Method, endpoint, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-Probe", scenario.Marker)
			request.Header.Set("User-Agent", "stackd-native-gateway-probe")
			for key, value := range row.RequestHeaders {
				request.Header.Set(key, value)
			}
			response, err := clients.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != row.Result.Status {
				t.Fatalf("%s status=%d native=%d body=%s", row.Label, response.StatusCode, row.Result.Status, body)
			}
			var actual map[string]any
			awsDecodeJSON(t, body, &actual)
			gatewayV2CredentialsBody(t, row.Label, actual, row.Result.Body, bindings)
			observed[scenario.Label] = true
		} else {
			row := fixture.Sockets[step.index]
			scenario := wireScenarios[row.Label]
			socket := sockets[row.Connection]
			switch row.Operation {
			case "connect":
				origin, err := url.Parse(row.Request.URL)
				if err != nil {
					t.Fatal(err)
				}
				nativeAPI, _, _ := strings.Cut(origin.Hostname(), ".")
				apiID, ok := bindings[nativeAPI]
				if !ok {
					t.Fatalf("%s has no established API for native endpoint %s", row.Label, row.Request.URL)
				}
				endpoint := "ws" + strings.TrimPrefix(clients.server.URL, "http") + "/_stackd/execute-api/" + apiID + origin.RequestURI()
				headers := make(http.Header)
				for key, value := range row.Request.Headers {
					headers.Set(key, value)
				}
				connection, status, _, body, dialErr := gatewayWSDial(t.Context(), endpoint, headers)
				if connection != nil {
					sockets[row.Connection] = connection
				}
				if status != row.Result.Status || status == 101 && dialErr != nil || status != 101 && dialErr == nil {
					t.Fatalf("%s handshake=%d native=%d body=%s error=%v", row.Label, status, row.Result.Status, body, dialErr)
				}
				if status != 101 {
					var actual, native map[string]any
					awsDecodeJSON(t, body, &actual)
					awsDecodeJSON(t, gatewayWSDecode64(t, row.Result.Body.Base64), &native)
					gatewayV2CredentialsBody(t, row.Label, actual, native, bindings)
				}
				observed[scenario.Label] = true
			case "send":
				if socket == nil {
					t.Fatalf("%s lost its held connection", row.Label)
				}
				if err := socket.Send(row.Request.Opcode, []byte(row.Request.Text)); err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
			case "receive", "close":
				if socket == nil {
					t.Fatalf("%s lost its held connection", row.Label)
				}
				if row.Operation == "close" {
					if err := socket.Send(ws.OpClose, ws.NewCloseFrameBody(ws.StatusCode(row.Request.CloseCode), row.Request.CloseReason)); err != nil {
						t.Fatalf("%s: %v", row.Label, err)
					}
				}
				payload, opcode, err := socket.Read(time.Duration(row.Request.TimeoutSeconds * float64(time.Second)))
				if err != nil || opcode != row.Result.Opcode || row.Result.Outcome != "frame" {
					t.Fatalf("%s opcode=%d body=%s error=%v native=%+v", row.Label, opcode, payload, err, row.Result)
				}
				if row.Operation == "close" {
					if !bytes.Equal(payload, gatewayWSDecode64(t, row.Result.Base64)) {
						t.Fatalf("%s close frame=%q native=%q", row.Label, payload, gatewayWSDecode64(t, row.Result.Base64))
					}
					_ = socket.Close()
					delete(sockets, row.Connection)
				} else {
					var actual map[string]any
					awsDecodeJSON(t, payload, &actual)
					gatewayV2CredentialsBody(t, row.Label, actual, row.Result.JSON, bindings)
					observed[scenario.Label] = true
				}
			default:
				t.Fatalf("unsupported native socket operation %s", row.Operation)
			}
		}
		wireCalls++
	}
	for label := range selected {
		if !observed[label] {
			t.Fatalf("native credential scenario not exercised: %s", label)
		}
	}
	gatewayV2CredentialsLogs(t, gatewaySDKClient(t, "logs", config(owner)).(*cloudwatchlogs.Client), "/aws/lambda/"+fixture.Owned.Function, fixture, markers, bindings)
	for name, socket := range sockets {
		_ = socket.Close()
		delete(sockets, name)
	}
	clients = reopen()
	for _, row := range durableReads {
		call(row)
	}
	t.Logf("replayed %d native controls and %d HTTP/socket operations; %d correlated scenarios across reopened %s; excluded %v; final readiness samples do not establish regional convergence timing", controls, wireCalls, len(selected), backend, excluded)
}

func gatewayV2CredentialsBody(t *testing.T, label string, actual, native map[string]any, bindings map[string]string) {
	t.Helper()
	want := gatewayClone(t, native)
	for _, field := range []string{"invocation_id", "connectionId", "requestId"} {
		if id, ok := want[field].(string); ok {
			gatewayWSAuthorizerBind(t, label+" "+field, id, actual[field], bindings)
		}
	}
	gatewaySubstitute(want, bindings)
	got := gatewayClone(t, actual)
	if _, present := want["message"]; present {
		// Diagnostic wording is not a credential authorization contract.
		if message, ok := got["message"].(string); !ok || message == "" {
			t.Fatalf("%s omitted error diagnosis: %v", label, actual)
		}
		got["message"] = want["message"]
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s body=%v native=%v", label, actual, want)
	}
}

func gatewayV2CredentialsLogs(t *testing.T, client *cloudwatchlogs.Client, group string, fixture gatewayV2CredentialsFixture, scenarios map[string]gatewayV2CredentialsScenario, bindings map[string]string) {
	t.Helper()
	expected := map[string][]gatewayV2CredentialsRecord{}
	count := 0
	for _, log := range fixture.Logs {
		if _, ok := scenarios[log.Record.Marker]; ok {
			expected[log.Record.Marker] = append(expected[log.Record.Marker], log.Record)
			count++
		}
	}
	for marker, scenario := range scenarios {
		if len(expected[marker]) != scenario.Invocations || len(scenario.InvocationIDs) != scenario.Invocations || scenario.BackendSuccess != (scenario.Invocations != 0) {
			t.Fatalf("%s native backend correlation is incomplete", scenario.Label)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var records []gatewayV2CredentialsRecord
	for {
		records = nil
		for _, message := range gatewayLogMessages(t, ctx, client, group, `"v2-integration-credentials"`) {
			var record gatewayV2CredentialsRecord
			if json.Unmarshal([]byte(strings.TrimSpace(message)), &record) == nil && record.Kind == "v2-integration-credentials" {
				records = append(records, record)
			}
		}
		if len(records) >= count {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("only %d/%d real integration invocation markers arrived", len(records), count)
		case <-time.After(25 * time.Millisecond):
		}
	}
	seen := map[string]int{}
	connections := map[string]any{}
	for _, record := range records {
		native := expected[record.Marker]
		index := seen[record.Marker]
		if index >= len(native) {
			t.Fatalf("unexpected backend invocation for marker %q; denied integrations must not invoke Lambda", record.Marker)
		}
		want := native[index]
		seen[record.Marker]++
		gatewayWSAuthorizerBind(t, record.Marker+" invocation", want.Invocation, record.Invocation, bindings)
		request := record.Event["requestContext"].(map[string]any)
		nativeRequest := want.Event["requestContext"].(map[string]any)
		if id, ok := nativeRequest["connectionId"].(string); ok {
			gatewayWSAuthorizerBind(t, record.Marker+" connection", id, request["connectionId"], bindings)
			local := request["connectionId"].(string)
			if connected, ok := request["connectedAt"].(float64); !ok || connected <= 0 {
				t.Fatalf("%s omitted its connection establishment time", record.Marker)
			}
			if previous, ok := connections[local]; ok && previous != request["connectedAt"] {
				t.Fatalf("%s changed held socket identity/time after credential deployment", record.Marker)
			}
			connections[local] = request["connectedAt"]
		}
		// Compare the customer-visible authority boundary without pinning
		// unrelated transport timestamps, generated request IDs or source IPs.
		for _, field := range []string{"body", "routeKey", "stageVariables", "isBase64Encoded"} {
			actual, got := record.Event[field]
			expected, present := want.Event[field]
			if got != present || !reflect.DeepEqual(actual, expected) {
				t.Fatalf("%s event %s=%v native=%v", record.Marker, field, record.Event[field], want.Event[field])
			}
		}
		for _, field := range []string{"routeKey", "eventType", "stage", "apiId", "accountId", "authorizer"} {
			value, present := nativeRequest[field]
			if text, ok := value.(string); ok {
				value = gatewayReplace(text, bindings)
			}
			actual, got := request[field]
			if got != present || !reflect.DeepEqual(actual, value) {
				t.Fatalf("%s requestContext %s=%v native=%v", record.Marker, field, request[field], value)
			}
		}
	}
	for marker, scenario := range scenarios {
		if seen[marker] != scenario.Invocations {
			t.Fatalf("%s invoked Lambda %d times; native=%d", scenario.Label, seen[marker], scenario.Invocations)
		}
	}
}
