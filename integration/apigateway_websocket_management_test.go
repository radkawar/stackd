package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/aws/aws-sdk-go-v2/service/apigatewaymanagementapi"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/gobwas/ws"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type gatewayWSManagementFixture struct {
	Account, Region string
	Identity        struct{ Arn string }
	HandlerSource   string `json:"handler_source"`
	Owned           struct {
		API string `json:"websocket_api"`
	}
	Observations []gatewaySDKObservation
	Sockets      []gatewayWSManagementSocketRow `json:"websocket_observations"`
	Connections  map[string]struct {
		ID, Stage, Marker string
	}
	HTTP []struct {
		Label, Method, URL, Authorization string
		StartedAt                         time.Time `json:"started_at"`
		Result                            struct {
			Status  int
			Headers [][]string
		}
	}
}

type gatewayWSManagementSocketRow struct {
	Label, Operation, Connection, Phase string
	StartedAt                           time.Time `json:"started_at"`
	Request                             struct {
		URL, Text      string
		Opcode         ws.OpCode
		TimeoutSeconds int    `json:"timeout_seconds"`
		CloseCode      uint16 `json:"close_code"`
		CloseReason    string `json:"close_reason"`
	}
	Result struct {
		Code       string
		HTTPStatus int `json:"http_status"`
		Frames     []struct {
			Opcode       ws.OpCode
			Fin          bool
			Text         *string
			Base64       string
			PayloadBytes int `json:"payload_bytes"`
			SHA256       string
		}
	}
}

// Capture the actual response, including successful 200/201/204 statuses that
// are otherwise discarded by the generated SDK operation outputs.
type gatewayWSManagementHTTP struct {
	client *http.Client
	status int
	header http.Header
	body   []byte
}

func (c *gatewayWSManagementHTTP) Do(request *http.Request) (*http.Response, error) {
	response, err := c.client.Do(request)
	if response != nil {
		c.status = response.StatusCode
		c.header = response.Header.Clone()
		c.body = nil
		if response.StatusCode >= http.StatusBadRequest {
			c.body, err = io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				return nil, err
			}
			response.Body = io.NopCloser(bytes.NewReader(c.body))
		}
	}
	return response, err
}

type gatewayWSManagementConnection struct {
	socket                                     *gatewayWSConn
	id                                         string
	closed                                     bool
	posted                                     bool
	connected                                  time.Time
	identity                                   map[string]any
	initialActive                              time.Time
	nativeConnected, nativeActive, localActive time.Time
}

func TestAPIGatewayNativeWebSocketManagement(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real WebSocket Lambda runtimes")
	}
	var fixture gatewayWSManagementFixture
	awsReadFixture(t, "apigateway/websocket_management.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
			defer cancel()
			source := clock.NewManual(fixture.Observations[0].StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return newLambdaDockerStack(t, config, nil)
			})
			delegated := gatewayNativeUser(t, clients, fixture.Account, fixture.Region, fixture.Identity.Arn)
			actors := map[string]credentials.StaticCredentialsProvider{fixture.Identity.Arn: delegated}
			bindings := map[string]string{}
			connections := map[string]*gatewayWSManagementConnection{}
			byNativeID := map[string]*gatewayWSManagementConnection{}
			for alias := range fixture.Connections {
				connections[alias] = &gatewayWSManagementConnection{}
			}
			// Always clean up sockets before retainedCloud's server cleanup, also
			// when a failed assertion interrupts the native close sequence.
			defer func() {
				for _, connection := range connections {
					if connection.socket != nil {
						_ = connection.socket.Close()
					}
				}
			}()
			localURL := func(native string, socket bool) string {
				t.Helper()
				parsed, err := url.Parse(native)
				if err != nil || parsed.Host != fixture.Owned.API+".execute-api."+fixture.Region+".amazonaws.com" {
					t.Fatalf("unexpected native execution endpoint %q: %v", native, err)
				}
				apiID := bindings[fixture.Owned.API]
				if apiID == "" {
					t.Fatal("execution endpoint used before CreateApi binding")
				}
				origin, err := url.Parse(clients.server.URL)
				if err != nil {
					t.Fatal(err)
				}
				parsed.Scheme, parsed.Host = origin.Scheme, origin.Host
				parsed.Path = "/_stackd/execute-api/" + apiID + gatewayReplace(parsed.Path, bindings)
				parsed.RawPath = ""
				if socket {
					parsed.Scheme = "ws"
				}
				return parsed.String()
			}
			newClient := func(service, endpoint string, creds credentials.StaticCredentialsProvider) (any, *gatewayWSManagementHTTP) {
				capture := &gatewayWSManagementHTTP{client: &http.Client{Transport: clients.server.Client().Transport, Timeout: 20 * time.Second}}
				return gatewaySDKClient(t, service, aws.Config{Region: fixture.Region, BaseEndpoint: &endpoint, Credentials: creds, HTTPClient: capture, RetryMaxAttempts: 1}), capture
			}
			type step struct {
				at    time.Time
				kind  string
				index int
			}
			var steps []step
			for index, row := range fixture.Observations {
				steps = append(steps, step{row.StartedAt, "sdk", index})
			}
			for index, row := range fixture.Sockets {
				steps = append(steps, step{row.StartedAt, "socket", index})
			}
			for index, row := range fixture.HTTP {
				steps = append(steps, step{row.StartedAt, "http", index})
			}
			sort.SliceStable(steps, func(i, j int) bool { return steps[i].at.Before(steps[j].at) })
			reopened := false
			sdkCalls, managementCalls, semanticCalls, socketCalls, httpCalls, exclusions, infrastructure := 0, 0, 0, 0, 0, 0, 0
			for _, step := range steps {
				if step.at.After(source.Now()) {
					source.Advance(step.at.Sub(source.Now()))
				}
				switch step.kind {
				case "sdk":
					row := fixture.Observations[step.index]
					if row.Phase == "cleanup" || row.Phase == "evidence" || row.Operation == "CreateFunction" && row.Result.Code != "Success" || row.Phase == "readiness" && row.Result.Code != "Success" {
						// Propagation samples and AWS evidence/cleanup are not semantic
						// outcomes. Successful readiness calls still mint real sessions.
						infrastructure++
						continue
					}
					if reason := gatewayWSManagementExclusion(row.Label); reason != "" {
						t.Logf("excluded %s: %s", row.Label, reason)
						exclusions++
						continue
					}
					input := gatewayClone(t, row.Input)
					gatewaySubstitute(input, bindings)
					if row.Operation == "CreateFunction" {
						input["Runtime"] = "python3.12"
						input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
					}
					if blob, ok := row.Input["Data"].(map[string]any); ok {
						data, err := base64.StdEncoding.DecodeString(blob["base64"].(string))
						if err != nil {
							t.Fatalf("%s: %v", row.Label, err)
						}
						// Go's SDK blob JSON is a base64 string, not the capture's
						// {base64: ...} wrapper. Preserve empty and invalid UTF-8 bytes.
						input["Data"] = data
					}
					creds, ok := actors[row.Actor.Arn]
					if !ok {
						t.Fatalf("%s: no established actor %s", row.Label, row.Actor.Arn)
					}
					endpoint := clients.server.URL
					var connection *gatewayWSManagementConnection
					if row.Service == "apigatewaymanagementapi" {
						endpoint = localURL(row.Endpoint, false)
						connection = byNativeID[row.Input["ConnectionId"].(string)]
						if connection == nil || connection.id == "" {
							t.Fatalf("%s: ID not learned from a real identify reply", row.Label)
						}
					}
					client, capture := newClient(row.Service, endpoint, creds)
					encoded, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					out, err := awstest.CallSDK(ctx, client, row.Operation, encoded)
					if capture.status != row.Result.HTTPStatus {
						t.Fatalf("%s: HTTP %d, native %d; error=%v", row.Label, capture.status, row.Result.HTTPStatus, err)
					}
					sdkCalls++
					if connection != nil {
						managementCalls++
						if row.Phase == "semantic" {
							semanticCalls++
						}
					}
					if row.Result.Code != "Success" {
						code := row.Result.Code
						if code == fmt.Sprint(row.Result.HTTPStatus) {
							// Botocore uses the status number for an empty unmodeled
							// error; the Go SDK calls that same wire response UnknownError.
							if row.RawResponse.BodyBase64 != "" || len(capture.body) != 0 || capture.header.Get("X-Amzn-Errortype") != "" || capture.header.Get("X-Amzn-Requestid") != "" {
								t.Fatalf("%s did not preserve the native empty unmodeled response", row.Label)
							}
							code = "UnknownError"
						}
						assertAPIError(t, err, code)
						var response *smithyhttp.ResponseError
						if !errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
							t.Fatalf("%s: SDK did not retain native HTTP %d: %v", row.Label, row.Result.HTTPStatus, err)
						}
						if row.Operation == "PostToConnection" && !connection.closed {
							gatewayWSManagementSilence(t, row.Label+" rejected delivery", connection.socket, 200*time.Millisecond)
						}
						continue
					}
					if err != nil {
						t.Fatalf("%s: %v", row.Label, err)
					}
					if row.Operation == "PostToConnection" {
						connection.posted = true
					}
					if got, ok := out.(*apigatewaymanagementapi.GetConnectionOutput); ok {
						gatewayWSManagementGet(t, row.Label, got, connection, row.Result.Output, source.Now())
						if connection.posted && !got.LastActiveAt.After(connection.initialActive) {
							t.Fatalf("%s: accepted post did not advance LastActiveAt beyond the live baseline", row.Label)
						}
						if row.Label == "payload-131073-survival" && !got.LastActiveAt.Equal(connection.initialActive) {
							t.Fatalf("%s: rejected oversize post changed LastActiveAt", row.Label)
						}
					}
					if session, ok := out.(*sts.AssumeRoleOutput); ok {
						nativeActor := row.Result.Output["AssumedRoleUser"].(map[string]any)["Arn"].(string)
						actors[nativeActor] = credentials.NewStaticCredentialsProvider(*session.Credentials.AccessKeyId, *session.Credentials.SecretAccessKey, *session.Credentials.SessionToken)
					}
					if connection == nil {
						encoded, err = json.Marshal(out)
						if err != nil {
							t.Fatal(err)
						}
						var actual map[string]any
						awsDecodeJSON(t, encoded, &actual)
						gatewayBind(row.Result.Output, actual, bindings)
					}
					if row.Operation == "CreateFunction" {
						function := input["FunctionName"].(string)
						if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(ctx, &awslambda.GetFunctionConfigurationInput{FunctionName: &function}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
							t.Fatalf("%s: %v", row.Label, err)
						}
					}
				case "http":
					row := fixture.HTTP[step.index]
					if reason := gatewayWSManagementExclusion(row.Label); reason != "" {
						t.Logf("excluded %s: %s", row.Label, reason)
						exclusions++
						continue
					}
					if row.Authorization != "none" {
						t.Fatalf("%s: unexpected raw HTTP authority %q", row.Label, row.Authorization)
					}
					var body io.Reader
					if row.Method == http.MethodPost {
						body = strings.NewReader("unsigned")
					}
					request, err := http.NewRequestWithContext(ctx, row.Method, localURL(row.URL, false), body)
					if err != nil {
						t.Fatal(err)
					}
					response, err := (&http.Client{Transport: clients.server.Client().Transport, Timeout: 10 * time.Second}).Do(request)
					if err != nil {
						t.Fatalf("%s: %v", row.Label, err)
					}
					_, readErr := io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if readErr != nil || response.StatusCode != row.Result.Status {
						t.Fatalf("%s: HTTP %d, native %d: %v", row.Label, response.StatusCode, row.Result.Status, readErr)
					}
					for _, header := range row.Result.Headers {
						if strings.EqualFold(header[0], "x-amzn-ErrorType") && response.Header.Get(header[0]) != header[1] {
							t.Fatalf("%s: error code=%q, native=%q", row.Label, response.Header.Get(header[0]), header[1])
						}
					}
					if row.Method == http.MethodPost {
						parsed, _ := url.Parse(row.URL)
						nativeID := parsed.Path[strings.LastIndexByte(parsed.Path, '/')+1:]
						gatewayWSManagementSilence(t, row.Label+" rejected delivery", byNativeID[nativeID].socket, 200*time.Millisecond)
					}
					httpCalls++
				case "socket":
					row := fixture.Sockets[step.index]
					connection := connections[row.Connection]
					if connection == nil {
						t.Fatalf("%s: no captured connection metadata", row.Label)
					}
					switch row.Operation {
					case "connect":
						if !reopened {
							// Persistence is exercised after deployment, before ANY socket:
							// retained config, not resurrection of an active TCP connection.
							clients = reopen()
							reopened = true
						}
						address := localURL(row.Request.URL, true)
						dialCtx, stop := context.WithTimeout(ctx, 15*time.Second)
						socket, status, _, body, err := gatewayWSDial(dialCtx, address, http.Header{"User-Agent": {"stackd-native-management-probe"}})
						stop()
						if socket != nil {
							connection.socket = socket
						}
						if err != nil || status != row.Result.HTTPStatus || row.Result.Code != "Connected" {
							t.Fatalf("%s: handshake=%d body=%q error=%v; native=%s/%d", row.Label, status, body, err, row.Result.Code, row.Result.HTTPStatus)
						}
					case "send":
						if err := connection.socket.Send(row.Request.Opcode, []byte(gatewayReplace(row.Request.Text, bindings))); err != nil {
							t.Fatalf("%s: %v", row.Label, err)
						}
					case "receive":
						timeout := time.Duration(row.Request.TimeoutSeconds) * time.Second
						if row.Result.Code == "Timeout" {
							gatewayWSManagementSilence(t, row.Label, connection.socket, timeout)
							break
						}
						want, wantOpcode := gatewayWSManagementMessage(t, row)
						got, opcode, err := connection.socket.Read(timeout)
						if err != nil || opcode != wantOpcode {
							t.Fatalf("%s: opcode=%d error=%v; native=%s opcode=%d", row.Label, opcode, err, row.Result.Code, wantOpcode)
						}
						if strings.HasPrefix(row.Label, "identify-receive-") {
							gatewayWSManagementIdentify(t, row.Label, got, want, connection, bindings, clients.server.URL)
							native := fixture.Connections[row.Connection]
							if bindings[native.ID] != connection.id {
								t.Fatalf("%s: identify reply did not bind native connection ID", row.Label)
							}
							for id, existing := range byNativeID {
								if id != native.ID && existing.id == connection.id {
									t.Fatalf("%s: live connection ID reused", row.Label)
								}
							}
							byNativeID[native.ID] = connection
							endpoint := localURL("https://"+fixture.Owned.API+".execute-api."+fixture.Region+".amazonaws.com/"+native.Stage, false)
							client, capture := newClient("apigatewaymanagementapi", endpoint, delegated)
							baseline, err := client.(*apigatewaymanagementapi.Client).GetConnection(ctx, &apigatewaymanagementapi.GetConnectionInput{ConnectionId: &connection.id})
							if err != nil || capture.status != http.StatusOK {
								t.Fatalf("%s activity baseline: HTTP %d: %v", row.Label, capture.status, err)
							}
							gatewayWSManagementGet(t, row.Label+" baseline", baseline, connection, nil, source.Now())
							connection.initialActive = *baseline.LastActiveAt
						} else if !bytes.Equal(got, want) {
							t.Fatalf("%s: complete message differs: got bytes=%d sha256=%x, native bytes=%d sha256=%x", row.Label, len(got), sha256.Sum256(got), len(want), sha256.Sum256(want))
						}
						if opcode == ws.OpClose {
							connection.closed = true
						}
					case "close":
						if !connection.closed {
							payload := ws.NewCloseFrameBody(ws.StatusCode(row.Request.CloseCode), row.Request.CloseReason)
							if err := connection.socket.Send(ws.OpClose, payload); err != nil {
								t.Fatalf("%s: %v", row.Label, err)
							}
							_, opcode, err := connection.socket.Read(time.Duration(row.Request.TimeoutSeconds) * time.Second)
							if err != nil || opcode != ws.OpClose {
								t.Fatalf("%s: close acknowledgement opcode=%d: %v", row.Label, opcode, err)
							}
							connection.closed = true
						}
						_ = connection.socket.Close()
						connection.socket = nil
					default:
						t.Fatalf("%s: unhandled socket operation %s", row.Label, row.Operation)
					}
					socketCalls++
				}
			}
			t.Logf("replayed %d SDK observations (%d management, %d semantic), %d socket observations, %d unsigned HTTP outcomes; %d live activity baselines; %d opaque-ID exclusions; %d propagation/evidence/cleanup samples not replayed", sdkCalls, managementCalls, semanticCalls, socketCalls, httpCalls, len(byNativeID), exclusions, infrastructure)
		})
	}
}

func gatewayWSManagementExclusion(label string) string {
	if strings.HasPrefix(label, "malformed-id-") || strings.HasPrefix(label, "missing-id-") || strings.HasPrefix(label, "denied-missing-id-") || label == "unsigned-missing-get" {
		return "native 400 uses an invented or mutated opaque ID whose validity was never established; this does not prove absent-valid-ID behavior. Real live/closed IDs, unsigned live 403 and repeated Gone 410 remain replayed"
	}
	return ""
}

func gatewayWSManagementSilence(t *testing.T, label string, socket *gatewayWSConn, timeout time.Duration) {
	t.Helper()
	payload, opcode, err := socket.Read(timeout)
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() || opcode != 0 || len(payload) != 0 {
		t.Fatalf("%s: expected no frame; opcode=%d bytes=%d error=%v", label, opcode, len(payload), err)
	}
}

// Native TCP/frame boundaries vary; reconstruct the complete native message,
// retaining its opcode and EVERY byte rather than comparing a prefix or length.
func gatewayWSManagementMessage(t *testing.T, row gatewayWSManagementSocketRow) ([]byte, ws.OpCode) {
	t.Helper()
	var payload []byte
	var opcode ws.OpCode
	finished := false
	for index, frame := range row.Result.Frames {
		var data []byte
		if frame.Text != nil {
			data = []byte(*frame.Text)
		} else {
			var err error
			data, err = base64.StdEncoding.DecodeString(frame.Base64)
			if err != nil {
				t.Fatalf("%s native frame %d: %v", row.Label, index, err)
			}
		}
		if len(data) != frame.PayloadBytes || fmt.Sprintf("%x", sha256.Sum256(data)) != frame.SHA256 {
			t.Fatalf("%s: incomplete native frame %d", row.Label, index)
		}
		if frame.Opcode == ws.OpPing || frame.Opcode == ws.OpPong {
			continue
		}
		if finished || opcode != 0 && frame.Opcode != ws.OpContinuation {
			t.Fatalf("%s: unexpected native message framing", row.Label)
		}
		if opcode == 0 {
			opcode = frame.Opcode
		}
		payload = append(payload, data...)
		finished = frame.Fin
	}
	if !finished || opcode == 0 || row.Result.Code != "Message" && row.Result.Code != "Close" {
		t.Fatalf("%s: incomplete native receive %s", row.Label, row.Result.Code)
	}
	return payload, opcode
}

func gatewayWSManagementIdentify(t *testing.T, label string, got, want []byte, connection *gatewayWSManagementConnection, bindings map[string]string, origin string) {
	t.Helper()
	var actual, expected map[string]any
	awsDecodeJSON(t, got, &actual)
	awsDecodeJSON(t, want, &expected)
	actualEvent, ok := actual["event"].(map[string]any)
	if !ok {
		t.Fatalf("%s: missing real Lambda event", label)
	}
	actualContext, ok := actualEvent["requestContext"].(map[string]any)
	if !ok {
		t.Fatalf("%s: missing requestContext", label)
	}
	expectedContext := expected["event"].(map[string]any)["requestContext"].(map[string]any)
	for _, field := range []string{"connectionId", "messageId", "requestId", "extendedRequestId"} {
		value, ok := actualContext[field].(string)
		if !ok || value == "" {
			t.Fatalf("%s: missing generated %s", label, field)
		}
		bindings[expectedContext[field].(string)] = value
	}
	invocation, ok := actual["invocation"].(string)
	if !ok || invocation == "" {
		t.Fatalf("%s: missing Lambda invocation ID", label)
	}
	bindings[expected["invocation"].(string)] = invocation
	connection.id = actualContext["connectionId"].(string)
	connected, connectedOK := actualContext["connectedAt"].(float64)
	requested, requestedOK := actualContext["requestTimeEpoch"].(float64)
	if !connectedOK || !requestedOK || connected <= 0 || requested < connected {
		t.Fatalf("%s: invalid connected/requested ordering: %v / %v", label, actualContext["connectedAt"], actualContext["requestTimeEpoch"])
	}
	connection.connected = time.UnixMilli(int64(connected))
	requestTime := time.UnixMilli(int64(requested))
	if actualContext["requestTime"] != requestTime.UTC().Format("02/Jan/2006:15:04:05 -0700") {
		t.Fatalf("%s: requestTime does not describe requestTimeEpoch", label)
	}
	// Substitute generated timestamps, never delete their presence or erase
	// ordering. Management assertions below preserve all subsequent transitions.
	expectedContext["connectedAt"] = connected
	expectedContext["requestTimeEpoch"] = requested
	expectedContext["requestTime"] = actualContext["requestTime"]
	identity, ok := actualContext["identity"].(map[string]any)
	if !ok {
		t.Fatalf("%s: missing socket identity", label)
	}
	sourceIP, ok := identity["sourceIp"].(string)
	if !ok || net.ParseIP(sourceIP) == nil {
		t.Fatalf("%s: invalid source IP %v", label, identity["sourceIp"])
	}
	connection.identity = identity
	expectedContext["identity"].(map[string]any)["sourceIp"] = sourceIP
	local, err := url.Parse(origin)
	if err != nil || actualContext["domainName"] != local.Host {
		t.Fatalf("%s: domainName=%v, local origin=%s", label, actualContext["domainName"], origin)
	}
	expectedContext["domainName"] = local.Host
	runtime, ok := actual["runtime"].(string)
	if !ok || !strings.HasPrefix(runtime, "3.12.") || actual["execution_environment"] != "AWS_Lambda_python3.12" {
		t.Fatalf("%s: reply did not come from the configured Python Lambda runtime: %v / %v", label, actual["runtime"], actual["execution_environment"])
	}
	expected["runtime"], expected["execution_environment"] = runtime, actual["execution_environment"]
	gatewaySubstitute(expected, bindings)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s: Lambda identify event differs\ngot %s\nnative with generated bindings %s", label, got, mustGatewayWSManagementJSON(t, expected))
	}
}

func mustGatewayWSManagementJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func gatewayWSManagementGet(t *testing.T, label string, got *apigatewaymanagementapi.GetConnectionOutput, connection *gatewayWSManagementConnection, native map[string]any, now time.Time) {
	t.Helper()
	if got.ConnectedAt == nil || got.LastActiveAt == nil || got.Identity == nil || got.Identity.SourceIp == nil || got.Identity.UserAgent == nil {
		t.Fatalf("%s: GetConnection omitted native ConnectedAt/Identity/LastActiveAt fields: %+v", label, got)
	}
	if got.ConnectedAt.UnixMilli() != connection.connected.UnixMilli() || got.LastActiveAt.Before(*got.ConnectedAt) || got.LastActiveAt.UnixMilli() > now.UnixMilli() {
		t.Fatalf("%s: ConnectedAt changed or activity is out of order: connected=%v identify=%v active=%v now=%v", label, got.ConnectedAt, connection.connected, got.LastActiveAt, now)
	}
	if *got.Identity.SourceIp != connection.identity["sourceIp"] || *got.Identity.UserAgent != connection.identity["userAgent"] {
		t.Fatalf("%s: management identity differs from live socket: %+v / %v", label, got.Identity, connection.identity)
	}
	if native == nil {
		return
	}
	nativeConnected, err := time.Parse(time.RFC3339Nano, native["ConnectedAt"].(string))
	if err != nil {
		t.Fatal(err)
	}
	nativeActive, err := time.Parse(time.RFC3339Nano, native["LastActiveAt"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !connection.nativeActive.IsZero() {
		if !nativeConnected.Equal(connection.nativeConnected) || nativeActive.Compare(connection.nativeActive) != got.LastActiveAt.Compare(connection.localActive) {
			t.Fatalf("%s: activity transition differs: native %v -> %v; local %v -> %v; ConnectedAt native %v -> %v", label, connection.nativeActive, nativeActive, connection.localActive, got.LastActiveAt, connection.nativeConnected, nativeConnected)
		}
	}
	nativeIdentity := native["Identity"].(map[string]any)
	if *got.Identity.UserAgent != nativeIdentity["UserAgent"] {
		t.Fatalf("%s: UserAgent=%q, native=%v", label, *got.Identity.UserAgent, nativeIdentity["UserAgent"])
	}
	connection.nativeConnected, connection.nativeActive, connection.localActive = nativeConnected, nativeActive, *got.LastActiveAt
}
