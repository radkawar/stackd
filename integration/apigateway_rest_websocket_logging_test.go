package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/gobwas/ws"
)

func TestAPIGatewayNativeRESTWebSocketLogging(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real Gateway logging runtimes")
	}
	var fixture gatewayLoggingFixture
	awsReadFixture(t, "apigateway/rest_websocket_logs.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newGatewayLoggingReplay(t, fixture, backend)
			for _, row := range fixture.Observations {
				if row.Label == "off-override-rest-config" {
					break
				}
				if strings.Contains(row.Label, "ready-") || row.Operation == "CreateFunction" && row.Result.Code != "Success" {
					continue
				}
				// AWS propagation retries and narrow-policy repeats are not
				// independent admission behavior. Keep the first narrow denial.
				if strings.Contains(row.Label, "-narrow-") && !strings.HasSuffix(row.Label, "-0") {
					continue
				}
				if strings.HasPrefix(row.Label, "account-set-owned-role-documented-") && row.Result.Code != "Success" {
					continue
				}
				if row.Label == "documented-logging-policy" || row.Label == "documented-logging-policy-version" {
					continue
				}
				if row.Label == "attach-documented-logging-policy" {
					r.installNativeLoggingPolicy()
					continue
				}
				// Execution groups must be created by Gateway, not by the test.
				// The capture initially guessed the wrong WS name; recovered
				// native events prove /aws/apigateway/{apiId}/{stage} instead.
				if row.Label == "create-group-rest_execution" || row.Label == "create-group-ws_execution" {
					continue
				}
				r.call(row)
			}
			for _, label := range []string{"error-rest-config", "error-ws-config", "error-rest", "error-ws"} {
				r.call(r.row(label))
			}
			for _, label := range []string{"info-trace-rest-config", "info-trace-ws-config", "info-trace-rest", "info-trace-ws"} {
				r.call(r.row(label))
			}
			r.clients = r.reopen()
			for _, label := range []string{"account-owned-role-read-documented-2", "info-trace-rest", "info-trace-ws"} {
				r.call(r.row(label))
			}
			groups := fixture.Owned["gateway_log_groups"].(map[string]any)
			// The native capture's late 'removed-*' traffic still observed its
			// prior settings. Replay those actual payloads under stable enabled
			// settings: neither five-second convergence nor precedence is proved
			// by that capture. Removal below tests control/history retention only.
			for index, row := range fixture.HTTP {
				if !strings.HasPrefix(row.Label, "removed-") && row.Label != "info-trace-rest-iam-denied" {
					continue
				}
				r.http(index)
				for _, correlation := range fixture.Correlations {
					if correlation.Label != row.Label {
						continue
					}
					for _, id := range correlation.LambdaEventIDs {
						r.application(r.event("lambda", id))
					}
					for _, id := range correlation.AccessEventIDs {
						r.access(groups["rest_access"].(string), r.event("rest_access", id))
					}
					r.execution("rest_execution", groups["rest_execution"].(string), correlation)
				}
			}
			r.loggingSocketCohort("removed")
			for _, correlation := range fixture.Correlations {
				if correlation.Protocol != "WEBSOCKET" {
					continue
				}
				application := r.event("lambda", correlation.LambdaEventID)
				// Include this connection's disconnect even though its marker is
				// null. Native request IDs identify its exact application record.
				var record struct {
					Event struct {
						RequestContext struct {
							ConnectionID string `json:"connectionId"`
						} `json:"requestContext"`
					}
				}
				awsDecodeJSON(t, []byte(application.Message), &record)
				if !strings.Contains(correlation.Marker, ":removed-") && r.bindings[record.Event.RequestContext.ConnectionID] == "" {
					continue
				}
				if !strings.Contains(correlation.Marker, ":removed-") && correlation.Marker != "" {
					continue
				}
				r.application(application)
				for _, id := range correlation.AccessEventIDs {
					r.access(groups["ws_access"].(string), r.event("ws_access", id))
				}
				r.execution("ws_execution", groups["recovered_ws_0"].(string), correlation)
			}
			var retained []gatewaySDKObservation
			for _, label := range []string{"rest-access-remove", "rest-method-override-remove", "rest-default-off", "ws-access-remove", "ws-route-override-remove", "ws-default-off", "removed-rest", "removed-ws"} {
				row := r.row(label)
				r.call(row)
				if row.Operation == "GetStage" {
					retained = append(retained, row)
				}
			}
			r.retain([]string{groups["rest_access"].(string), groups["ws_access"].(string), groups["rest_execution"].(string), groups["recovered_ws_0"].(string)}, retained)
			for _, row := range fixture.Observations {
				if (row.Service == "apigateway" || row.Service == "apigatewayv2") && (strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "absence-") || row.Label == "restore-account-empty") {
					r.call(row)
				}
			}
		})
	}
}

func (r *gatewayLoggingReplay) installNativeLoggingPolicy() {
	t := r.t
	t.Helper()
	version := r.row("documented-logging-policy-version").Result.Output["PolicyVersion"].(map[string]any)
	document, err := json.Marshal(version["Document"])
	if err != nil {
		t.Fatal(err)
	}
	// Use the captured AWS managed policy's actual document as an inline
	// policy; do not require an unrelated emulator managed-policy catalogue.
	_, err = iam.NewFromConfig(r.config(r.owner)).PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName: aws.String(r.fixture.Owned["logging_role"].(string)), PolicyName: aws.String("captured-gateway-logs"), PolicyDocument: aws.String(string(document)),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (r *gatewayLoggingReplay) event(group, id string) gatewayLoggingEvent {
	r.t.Helper()
	for _, event := range r.fixture.RawLogs[group] {
		if event.EventID == id {
			return event
		}
	}
	r.t.Fatalf("native %s event %s missing", group, id)
	return gatewayLoggingEvent{}
}

func (r *gatewayLoggingReplay) loggingSocketCohort(connection string) {
	t := r.t
	t.Helper()
	var socket *gatewayWSConn
	defer func() {
		if socket != nil {
			_ = socket.Close()
		}
	}()
	for _, row := range r.fixture.Sockets {
		if row.Connection != connection {
			continue
		}
		switch row.Operation {
		case "connect":
			headers := http.Header{}
			for name, value := range row.Request.Headers {
				headers.Set(name, value)
			}
			var status int
			var body []byte
			var err error
			socket, status, _, body, err = gatewayWSDial(t.Context(), r.localURL(row.Request.URL, true), headers)
			if err != nil || status != row.Result.Status {
				t.Fatalf("%s handshake=%d native=%d body=%s: %v", row.Label, status, row.Result.Status, body, err)
			}
		case "send":
			if err := socket.Send(row.Request.Opcode, []byte(row.Request.Text)); err != nil {
				t.Fatal(err)
			}
		case "receive":
			payload, opcode, err := socket.Read(5 * time.Second)
			if err != nil || opcode != row.Result.Opcode {
				t.Fatalf("%s opcode=%d native=%d: %s %v", row.Label, opcode, row.Result.Opcode, payload, err)
			}
			var actual map[string]any
			awsDecodeJSON(t, payload, &actual)
			for _, key := range []string{"probe_kind", "marker", "mode", "message"} {
				if expected, ok := row.Result.JSON[key]; ok && actual[key] != expected {
					t.Fatalf("%s %s=%v native=%v", row.Label, key, actual[key], expected)
				}
			}
			for _, key := range []string{"invocation", "requestId", "connectionId"} {
				if before, ok := row.Result.JSON[key].(string); ok {
					after, _ := actual[key].(string)
					if after == "" {
						t.Fatalf("%s missing %s", row.Label, key)
					}
					if bound, ok := r.bindings[before]; ok && bound != after {
						t.Fatalf("%s changed bound %s", row.Label, key)
					}
					r.bindings[before] = after
				}
			}
			if event, ok := row.Result.JSON["event"].(map[string]any); ok {
				local := actual["event"].(map[string]any)["requestContext"].(map[string]any)
				for _, key := range []string{"requestId", "connectionId", "extendedRequestId", "messageId"} {
					before, _ := event["requestContext"].(map[string]any)[key].(string)
					after, _ := local[key].(string)
					if before == "" || after == "" {
						t.Fatalf("%s missing socket runtime %s", row.Label, key)
					}
					r.bindings[before] = after
				}
			}
		case "close":
			if err := socket.Send(ws.OpClose, ws.NewCloseFrameBody(ws.StatusCode(row.Request.CloseCode), row.Request.CloseReason)); err != nil {
				t.Fatal(err)
			}
			payload, opcode, err := socket.Read(5 * time.Second)
			want, decodeErr := base64.StdEncoding.DecodeString(row.Result.Base64)
			if err != nil || decodeErr != nil || opcode != row.Result.Opcode || !reflect.DeepEqual(payload, want) {
				t.Fatalf("%s close=%d %q native=%q: %v %v", row.Label, opcode, payload, want, err, decodeErr)
			}
			_ = socket.Close()
			socket = nil
		default:
			t.Fatalf("unhandled logging socket operation %s", row.Operation)
		}
	}
}

func (r *gatewayLoggingReplay) execution(alias, group string, correlation gatewayLoggingCorrelation) {
	r.t.Helper()
	if len(correlation.ExecutionEventIDs) == 0 {
		return
	}
	requestID := r.bindings[correlation.RequestID]
	if requestID == "" {
		r.t.Fatalf("execution lacks request correlation %s", correlation.RequestID)
	}
	var nativeApplication gatewayLoggingEvent
	if correlation.LambdaEventID != "" {
		nativeApplication = r.event("lambda", correlation.LambdaEventID)
	} else if len(correlation.LambdaEventIDs) != 0 {
		nativeApplication = r.event("lambda", correlation.LambdaEventIDs[0])
	}
	var application map[string]any
	awsDecodeJSON(r.t, []byte(nativeApplication.Message), &application)
	invocation := r.bindings[application["invocation"].(string)]
	marker, _ := application["marker"].(string)
	traceObserved, failureObserved := false, false
	for _, id := range correlation.ExecutionEventIDs {
		message := r.event(alias, id).Message
		if marker != "" && strings.Contains(message, marker) && strings.Contains(message, "request body after transformations:") {
			traceObserved = true
		}
		if strings.Contains(message, "owned-backend-failure") {
			failureObserved = true
		}
	}
	r.awaitMessages(group, func(messages []string) bool {
		endpointID, traced, failure := false, !traceObserved, !failureObserved
		for _, message := range messages {
			if !strings.Contains(message, requestID) {
				continue
			}
			if strings.Contains(message, invocation) {
				endpointID = true
			}
			if marker != "" && strings.Contains(message, marker) {
				traced = true
			}
			if strings.Contains(message, "owned-backend-failure") {
				failure = true
			}
		}
		return endpointID && traced && failure
	})
}
