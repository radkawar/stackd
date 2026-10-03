package stackd_test

import (
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type ecsAuditCapture struct {
	Event  map[string]any `json:"event"`
	Lookup struct {
		Username  string
		Resources []trailtypes.Resource
	} `json:"lookup"`
	Correlation *struct {
		Label string `json:"label"`
	} `json:"capture_correlation"`
}

func ecsAuditCaptures(t *testing.T) (map[string]ecsAuditCapture, []ecsControlRow) {
	t.Helper()
	captures := make(map[string]ecsAuditCapture)
	var controls []ecsControlRow
	for _, name := range []string{"audit.json", "audit_environment.json"} {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "ecs", name))
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Events []ecsAuditCapture
			Source []struct {
				Calls []struct {
					Code      string
					Input     json.RawMessage
					StartedAt time.Time `json:"started_at"`
					RequestID string    `json:"response_request_id"`
				}
			}
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		for _, row := range fixture.Events {
			if row.Correlation != nil && row.Correlation.Label != "" {
				if _, exists := captures[row.Correlation.Label]; exists {
					t.Fatalf("ambiguous native correlation %q", row.Correlation.Label)
				}
				captures[row.Correlation.Label] = row
			}
		}
		// The environment supplement retains CLI inputs beside its native
		// CloudTrail documents. Only request-ID-correlated calls are replayed.
		for _, source := range fixture.Source {
			for _, call := range source.Calls {
				for _, row := range fixture.Events {
					if row.Correlation != nil && call.RequestID == row.Event["requestID"] {
						controls = append(controls, ecsControlRow{Label: row.Correlation.Label, Service: "ecs", Operation: row.Event["eventName"].(string), Region: row.Event["awsRegion"].(string), Code: call.Code, Input: call.Input, StartedAt: call.StartedAt})
					}
				}
			}
		}
	}
	return captures, controls
}

func TestECSNativeAuditProjections(t *testing.T) {
	// The two uncorrelated calls are lifecycle prerequisites, not additional
	// native audit claims. Everything asserted below has a retained correlation.
	steps := []struct {
		label string
		audit bool
	}{
		{"cluster-create-defaults", true},
		{"cluster-describe-default", true},
		{"cluster-repeat-create-different", true},
		{"cluster-update-configuration", true},
		{"cluster-update-settings", true},
		{"cluster-untag-existing-missing", true},
		{"cluster-delete-first", true},
		{"task-register-revision-1-defaults", true},
		{"task-register-revision-2-identical", false},
		{"task-describe-qualified-tags", true},
		{"task-tag-merge-revision-1", true},
		{"task-untag", true},
		{"task-deregister-latest-qualified", false},
		{"task-deregister-revision-1", true},
		{"task-delete-inactive-and-missing", true},
		{"fargate-all-nonessential", true},
		{"environment-RegisterTaskDefinition", true},
		{"environment-DeregisterTaskDefinition", true},
		{"environment-DeleteTaskDefinitions", true},
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			controls := ecsControls(t)
			captures, environment := ecsAuditCaptures(t)
			controls.Calls = append(controls.Calls, environment...)
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "ecs-audit.sqlite"))
			}
			source := clock.NewManual(controls.Calls[0].StartedAt)
			cloud, err := stackd.New(stackd.Config{AccountID: "000000000000", Storage: backends, Clock: source})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cloud.Close(); err != nil {
					t.Error(err)
				}
			})
			server := httptest.NewServer(cloud)
			t.Cleanup(server.Close)
			clients := cloudClients{server}
			actor, key, secret := clients.user(t, "test", "Delegated")
			putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"*"`, "*"))
			user, err := clients.iam("test", "test", "").GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("Delegated")})
			if err != nil {
				t.Fatal(err)
			}
			provider := credentials.NewStaticCredentialsProvider(key, secret, "")
			wire := &awstest.WireClient{Client: server.Client()}
			client := ecs.New(ecs.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: provider, HTTPClient: wire, RetryMaxAttempts: 1})
			trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: provider, RetryMaxAttempts: 1})
			timestamps := map[string]map[string]string{}
			for _, step := range steps {
				if !t.Run(step.label, func(t *testing.T) {
					var row *ecsControlRow
					for i := range controls.Calls {
						if controls.Calls[i].Label == step.label {
							row = &controls.Calls[i]
							break
						}
					}
					if row == nil {
						t.Fatalf("missing native control %s", step.label)
					}
					if row.StartedAt.After(source.Now()) {
						source.Advance(row.StartedAt.Sub(source.Now()))
					}
					output, callErr := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
					if row.Code != "Success" {
						assertAPIError(t, callErr, row.Code)
					} else if callErr != nil {
						t.Fatal(callErr)
					}
					requestID := nativeAuditRequestID(t, output, callErr)
					if callErr == nil {
						body := ecsControlBody(t, wire.Body)
						if definition, ok := body["taskDefinition"].(map[string]any); ok {
							arn := definition["taskDefinitionArn"].(string)
							if row.Operation == "RegisterTaskDefinition" {
								timestamps[arn] = map[string]string{"registeredAt": source.Now().UTC().Format(time.RFC3339)}
							}
							if row.Operation == "DeregisterTaskDefinition" && definition["previousStatus"] == "ACTIVE" {
								timestamps[arn]["deregisteredAt"] = source.Now().UTC().Format(time.RFC3339)
							}
						}
					}
					if !step.audit {
						return
					}
					capture, ok := captures[step.label]
					if !ok {
						t.Fatalf("missing correlated native audit %s", step.label)
					}
					want := capture.Event
					want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
					ecsAuditRelocateTimes(want["responseElements"], timestamps)
					got := auditLookupRecord(t, trails, requestID, row.Operation)
					// Set-valued native output ordering is not significant; all
					// response fields, nulls, redactions and status history remain.
					for _, document := range []map[string]any{got, want} {
						if response, ok := document["responseElements"].(map[string]any); ok {
							ecsControlCanonical(response, row.Operation)
						}
					}
					var message string
					var apiError smithy.APIError
					if errors.As(callErr, &apiError) {
						message = apiError.ErrorMessage()
					}
					assertNativeAuditEvent(t, got, want, message)
					if _, present := got["apiVersion"]; present {
						t.Fatalf("native ECS event omits apiVersion: %#v", got)
					}
					identity := got["userIdentity"].(map[string]any)
					nativeIdentity := want["userIdentity"].(map[string]any)
					for _, field := range []string{"type", "accountId", "arn", "userName"} {
						if identity[field] != nativeIdentity[field] {
							t.Fatalf("actor %s: got %#v native %#v", field, identity[field], nativeIdentity[field])
						}
					}
					if identity["arn"] != actor || identity["principalId"] != aws.ToString(user.User.UserId) || identity["accessKeyId"] != key {
						t.Fatalf("audit did not retain authenticated actor: %#v", identity)
					}
					ip, _ := got["sourceIPAddress"].(string)
					if parsed := net.ParseIP(ip); parsed == nil || !parsed.IsLoopback() {
						t.Fatalf("audit source address %q", ip)
					}
					agent, _ := got["userAgent"].(string)
					if !strings.HasPrefix(agent, "aws-sdk-go-v2/") {
						t.Fatalf("audit lost SDK user agent: %q", agent)
					}
					lookup, err := trails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventId, AttributeValue: aws.String(got["eventID"].(string))}}})
					if err != nil {
						t.Fatal(err)
					}
					if len(lookup.Events) != 1 {
						t.Fatalf("lookup event ID returned %d events", len(lookup.Events))
					}
					event := lookup.Events[0]
					if aws.ToString(event.Username) != capture.Lookup.Username || len(event.Resources) != len(capture.Lookup.Resources) {
						t.Fatalf("native lookup metadata: got %#v want %#v", event, capture.Lookup)
					}
					for i, resource := range event.Resources {
						native := capture.Lookup.Resources[i]
						if aws.ToString(resource.ResourceType) != aws.ToString(native.ResourceType) || aws.ToString(resource.ResourceName) != aws.ToString(native.ResourceName) {
							t.Fatalf("lookup resource: got %#v native %#v", resource, native)
						}
					}
				}) {
					return
				}
			}
		})
	}
}

// Relocate only service-clock timestamps. Native second-resolution formatting
// remains observable and the fixture is otherwise independent of the API output.
func ecsAuditRelocateTimes(value any, timestamps map[string]map[string]string) {
	switch value := value.(type) {
	case map[string]any:
		if arn, ok := value["taskDefinitionArn"].(string); ok {
			for field, timestamp := range timestamps[arn] {
				if _, present := value[field]; present {
					value[field] = timestamp
				}
			}
		}
		for _, child := range value {
			ecsAuditRelocateTimes(child, timestamps)
		}
	case []any:
		for _, child := range value {
			ecsAuditRelocateTimes(child, timestamps)
		}
	}
}

func TestECSGeneratedExecutionRejectionsReachCloudTrail(t *testing.T) {
	body, err := os.ReadFile("../testdata/aws/ecs/audit_execution_rejections.json")
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Calls  []ecsControlRow
		Events []map[string]any
	}
	if err := json.Unmarshal(body, &native); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000"})
			provider := credentials.NewStaticCredentialsProvider("test", "test", "")
			for _, row := range native.Calls {
				t.Run(row.Operation, func(t *testing.T) {
					client := ecs.New(ecs.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: provider, RetryMaxAttempts: 1})
					output, rejected := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
					// Native RunTask resolves the missing definition before the
					// missing cluster. StartTask remains unsupported; only its
					// failure projection, not its API parity, is covered here.
					code := row.Code
					if row.Operation == "StartTask" {
						code = "NotImplementedException"
					}
					assertAPIError(t, rejected, code)
					var apiError smithy.APIError
					if !errors.As(rejected, &apiError) {
						t.Fatalf("execution rejection is not an API error: %v", rejected)
					}
					requestID := nativeAuditRequestID(t, output, rejected)
					clients = reopen()
					trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: provider, RetryMaxAttempts: 1})
					got := auditLookupRecord(t, trails, requestID, row.Operation)
					var want map[string]any
					for _, event := range native.Events {
						if event["eventName"] == row.Operation {
							want = event
							break
						}
					}
					if want == nil {
						t.Fatalf("missing native rejection projection for %s", row.Operation)
					}
					for _, field := range []string{"eventSource", "eventType", "eventCategory", "readOnly", "managementEvent", "requestParameters", "responseElements"} {
						if !reflect.DeepEqual(got[field], want[field]) {
							t.Fatalf("%s.%s: got %#v, native %#v", row.Operation, field, got[field], want[field])
						}
					}
					if got["errorCode"] != apiError.ErrorCode() || got["errorMessage"] != apiError.ErrorMessage() {
						t.Fatalf("audit concealed execution rejection: %#v", got)
					}
				})
			}
		})
	}
}
