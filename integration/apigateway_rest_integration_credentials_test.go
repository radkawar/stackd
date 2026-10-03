package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type restIntegrationCredentialsFixture struct {
	gatewayTimelineFixture
	HTTP                     []restIntegrationCredentialsHTTP
	CallerContextCapture     *restIntegrationCredentialsFixture `json:"caller_context_capture"`
	ExplicitNullWireRequests []struct {
		Label string
		Body  map[string]any
	} `json:"explicit_null_wire_requests"`
	Logs []struct{ Record restIntegrationCredentialsLog } `json:"invocation_logs"`
}

type restIntegrationCredentialsHTTP struct {
	Label, API, Path, Method, Phase, Authorization string
	StartedAt                                      time.Time         `json:"started_at"`
	RequestHeaders                                 map[string]string `json:"request_headers"`
	Actor                                          struct{ Arn string }
	Result                                         struct {
		Status  int
		Body    map[string]any
		Headers [][]string
	}
}

type restIntegrationCredentialsLog struct {
	ProbeKind         string `json:"probe_kind"`
	Invocation, Probe string
	LambdaRequestID   string `json:"lambdaRequestId"`
	FunctionARN       string `json:"invoked_function_arn"`
	Event             map[string]any
}

func TestAPIGatewayRESTIntegrationCredentialsNative(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real integration credential runtimes")
	}
	var fixture restIntegrationCredentialsFixture
	awsReadFixture(t, "apigateway/rest_integration_credentials.json", &fixture)
	if fixture.CallerContextCapture == nil {
		t.Fatal("native caller-forwarding context capture is missing")
	}
	captures := []struct {
		name    string
		fixture *restIntegrationCredentialsFixture
	}{{"credentials", &fixture}, {"caller-context", fixture.CallerContextCapture}}
	for _, capture := range captures {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(capture.name+"/"+backend, func(t *testing.T) {
				replayRESTIntegrationCredentials(t, *capture.fixture, backend)
			})
		}
	}
}

func replayRESTIntegrationCredentials(t *testing.T, fixture restIntegrationCredentialsFixture, backend string) {
	t.Helper()
	source := clock.NewManual(fixture.Observations[0].StartedAt)
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	primary := gatewayNativeUser(t, clients, fixture.Account, fixture.Region, fixture.Identity.Arn)
	actors := map[string]credentials.StaticCredentialsProvider{fixture.Identity.Arn: primary}
	bindings := map[string]string{}
	apiID := ""
	functionName := ""
	invocations := map[string]bool{}
	expectedLogs := map[string]restIntegrationCredentialsLog{}
	nativeLogs := map[string]restIntegrationCredentialsLog{}
	nativeMarkers := map[string]int{}
	for _, entry := range fixture.Logs {
		if entry.Record.ProbeKind == "backend" {
			nativeLogs[entry.Record.Invocation] = entry.Record
			nativeMarkers[entry.Record.Probe]++
		}
	}
	checkLogs := func() {
		t.Helper()
		restIntegrationCredentialsLogs(t, logsClient(clients, fixture.Account), "/aws/lambda/"+functionName, expectedLogs, bindings)
	}
	var snapshotCurrent *gatewaySDKObservation

	call := func(row gatewaySDKObservation) {
		t.Helper()
		input := gatewayClone(t, row.Input)
		gatewaySubstitute(input, bindings)
		if row.Operation == "CreateFunction" {
			input["Runtime"] = "python3.12"
			input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
		}
		actor := primary
		if row.Actor.Arn != "" {
			var ok bool
			actor, ok = actors[row.Actor.Arn]
			if !ok {
				t.Fatalf("%s has no established actor %s", row.Label, row.Actor.Arn)
			}
		}
		wire := &awstest.WireClient{Client: clients.server.Client()}
		config := aws.Config{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: actor, HTTPClient: wire, RetryMaxAttempts: 1}
		for _, nativeWire := range fixture.ExplicitNullWireRequests {
			if nativeWire.Label != row.Label {
				continue
			}
			// A nil SDK pointer omits credentials. Restore the captured literal-null
			// JSON before SDK content-length calculation and request signing.
			body := gatewayClone(t, nativeWire.Body)
			gatewaySubstitute(body, bindings)
			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			config.APIOptions = append(config.APIOptions, func(stack *middleware.Stack) error {
				return stack.Build.Add(middleware.BuildMiddlewareFunc("NativeIntegrationCredentialsBody", func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
					request, err := in.Request.(*smithyhttp.Request).SetStream(bytes.NewReader(payload))
					if err != nil {
						return middleware.BuildOutput{}, middleware.Metadata{}, err
					}
					in.Request = request
					return next.HandleBuild(ctx, in)
				}), middleware.Before)
			})
		}
		client := gatewaySDKClient(t, row.Service, config)
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		out, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
		if wire.Status != row.Result.HTTPStatus {
			t.Fatalf("%s HTTP status=%d native=%d: %v", row.Label, wire.Status, row.Result.HTTPStatus, err)
		}
		if row.Result.Code != "Success" {
			assertAPIError(t, err, row.Result.Code)
			return
		}
		if err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
		if session, ok := out.(*sts.AssumeRoleOutput); ok {
			nativeActor := row.Result.Output["AssumedRoleUser"].(map[string]any)["Arn"].(string)
			actors[nativeActor] = credentials.NewStaticCredentialsProvider(*session.Credentials.AccessKeyId, *session.Credentials.SecretAccessKey, *session.Credentials.SessionToken)
		}
		if row.Service == "apigateway" {
			var actual map[string]any
			awsDecodeJSON(t, wire.Body, &actual)
			want := gatewayClone(t, row.Result.Output)
			gatewaySubstitute(want, bindings)
			switch row.Operation {
			case "PutIntegration", "GetIntegration", "UpdateIntegration":
				restIntegrationCredentialFields(t, row.Label, actual, want, "credentials", "uri")
			case "GetMethod", "UpdateMethod":
				restIntegrationCredentialFields(t, row.Label, actual, want, "authorizationType")
				gotIntegration, gotPresent := actual["methodIntegration"].(map[string]any)
				wantIntegration, wantPresent := want["methodIntegration"].(map[string]any)
				if gotPresent != wantPresent {
					t.Fatalf("%s method integration presence differs", row.Label)
				}
				if wantPresent {
					restIntegrationCredentialFields(t, row.Label, gotIntegration, wantIntegration, "credentials", "uri")
				}
			}
		}
		encoded, err = json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]any
		awsDecodeJSON(t, encoded, &actual)
		gatewayBind(row.Result.Output, actual, bindings)
		if row.Operation == "CreateRestApi" {
			apiID = actual["Id"].(string)
		}
		if row.Operation == "CreateFunction" {
			functionName = actual["FunctionName"].(string)
			if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &functionName}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
				t.Fatalf("%s: %v", row.Label, err)
			}
		}
	}

	invoke := func(row restIntegrationCredentialsHTTP) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), row.Method, clients.server.URL+"/_stackd/execute-api/"+apiID+row.Path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range row.RequestHeaders {
			switch strings.ToLower(name) {
			case "authorization", "x-amz-date", "x-amz-security-token":
				continue
			}
			request.Header.Set(name, gatewayReplace(value, bindings))
		}
		request.Header.Set("Accept-Encoding", "identity")
		if row.Authorization == "iam" {
			actor, ok := actors[row.Actor.Arn]
			if !ok {
				t.Fatalf("%s has no signing actor %s", row.Label, row.Actor.Arn)
			}
			identity, err := actor.Retrieve(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(nil)
			if err := v4.NewSigner().SignHTTP(t.Context(), identity, request, hex.EncodeToString(digest[:]), "execute-api", fixture.Region, time.Now()); err != nil {
				t.Fatal(err)
			}
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
			t.Fatalf("%s status=%d native=%d: %s", row.Label, response.StatusCode, row.Result.Status, body)
		}
		var actual map[string]any
		awsDecodeJSON(t, body, &actual)
		marker := request.Header.Get("X-Probe")
		if marker == "" {
			t.Fatalf("%s has no native invocation marker", row.Label)
		}
		if row.Result.Status != http.StatusOK {
			if nativeMarkers[marker] != 0 {
				t.Fatalf("%s native denial unexpectedly invoked Lambda", row.Label)
			}
			if len(actual) != len(row.Result.Body) {
				t.Fatalf("%s error envelope differs: %s", row.Label, body)
			}
			for name, want := range row.Result.Body {
				got, present := actual[name]
				if !present || reflect.TypeOf(got) != reflect.TypeOf(want) {
					t.Fatalf("%s error field %s differs: %s", row.Label, name, body)
				}
			}
			for _, header := range row.Result.Headers {
				if len(header) == 2 && strings.EqualFold(header[0], "x-amzn-ErrorType") && response.Header.Get(header[0]) != header[1] {
					t.Fatalf("%s native error classification lost: %v", row.Label, response.Header)
				}
			}
			return
		}
		id, _ := actual["backendInvocationId"].(string)
		if id == "" || invocations[id] {
			t.Fatalf("%s did not execute a fresh backend invocation: %v", row.Label, actual)
		}
		invocations[id] = true
		nativeID, _ := row.Result.Body["backendInvocationId"].(string)
		nativeLog, present := nativeLogs[nativeID]
		if !present || nativeLog.Probe != marker {
			t.Fatalf("%s native HTTP result lacks a matching Lambda log witness", row.Label)
		}
		expectedLogs[id] = nativeLog
		got, ok := actual["event"].(map[string]any)
		if !ok {
			t.Fatalf("%s missing actual Lambda event", row.Label)
		}
		want := gatewayClone(t, row.Result.Body["event"].(map[string]any))
		gatewaySubstitute(want, bindings)
		gotIdentity := got["requestContext"].(map[string]any)["identity"].(map[string]any)
		wantIdentity := want["requestContext"].(map[string]any)["identity"].(map[string]any)
		restIntegrationCredentialFields(t, row.Label, gotIdentity, wantIdentity, "userArn", "accountId")
		gatewayCompareEvent(t, got, want, bindings)
	}

	type step struct {
		at    time.Time
		index int
		http  bool
	}
	var steps []step
	for i, row := range fixture.Observations {
		steps = append(steps, step{row.StartedAt, i, false})
	}
	for i, row := range fixture.HTTP {
		steps = append(steps, step{row.StartedAt, i, true})
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].at.Before(steps[j].at) })
	for _, step := range steps {
		if step.at.After(source.Now()) {
			source.Advance(step.at.Sub(source.Now()))
		}
		if !step.http {
			row := fixture.Observations[step.index]
			// Successful readiness operations establish deployments and sessions;
			// transient propagation failures are not an admission contract.
			if row.Phase == "cleanup" || strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "absence-") || fixture.ReplayExclusions[row.Label] != "" || row.Service == "logs" && row.Operation != "CreateLogGroup" || row.Phase == "readiness" && row.Result.Code != "Success" || row.Operation == "CreateFunction" && row.Result.Code != "Success" {
				continue
			}
			call(row)
			if row.Operation == "GetIntegration" && strings.HasPrefix(row.Label, "snapshot-update-") {
				snapshotCurrent = &row
			}
			continue
		}
		row := fixture.HTTP[step.index]
		// Native bounded propagation samples are evidence for the later semantic
		// observation, not a deterministic retry schedule for the local runtime.
		if row.Phase != "semantic" || fixture.ReplayExclusions[row.Label] != "" {
			continue
		}
		invoke(row)
		if strings.HasPrefix(row.Label, "snapshot-") && strings.HasSuffix(row.Label, "-before-deployment") {
			if snapshotCurrent == nil {
				t.Fatalf("%s has no captured current integration", row.Label)
			}
			// Exercise the live held deployment first. Reopening must preserve both
			// its old authority and the different current control-plane credentials.
			checkLogs()
			clients = reopen()
			call(*snapshotCurrent)
			invoke(row)
		}
		if row.Label == "context-plain-after-sentinel" {
			checkLogs()
			clients = reopen()
			invoke(row)
		}
	}
	checkLogs()
}

func restIntegrationCredentialFields(t *testing.T, label string, got, want map[string]any, names ...string) {
	t.Helper()
	for _, name := range names {
		actual, present := got[name]
		expected, nativePresent := want[name]
		if present != nativePresent || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s %s=%v (present %t), native=%v (present %t)", label, name, actual, present, expected, nativePresent)
		}
	}
}

func restIntegrationCredentialsLogs(t *testing.T, client *cloudwatchlogs.Client, group string, expected map[string]restIntegrationCredentialsLog, bindings map[string]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for {
		records := map[string]restIntegrationCredentialsLog{}
		for _, message := range gatewayLogMessages(t, ctx, client, group, `"backend"`) {
			var record restIntegrationCredentialsLog
			if json.Unmarshal([]byte(strings.TrimSpace(message)), &record) != nil || record.ProbeKind != "backend" {
				continue
			}
			native, present := expected[record.Invocation]
			if !present || native.Probe != record.Probe {
				t.Fatalf("unexpected Lambda execution for marker %q (including denied requests): %+v", record.Probe, record)
			}
			if _, duplicate := records[record.Invocation]; duplicate {
				t.Fatalf("duplicate backend invocation log for marker %q", record.Probe)
			}
			records[record.Invocation] = record
		}
		if len(records) == len(expected) {
			requests := map[string]bool{}
			for id, record := range records {
				native := expected[id]
				if record.LambdaRequestID == "" || requests[record.LambdaRequestID] {
					t.Fatalf("marker %q has no distinct Lambda request identity", record.Probe)
				}
				requests[record.LambdaRequestID] = true
				if record.FunctionARN != gatewayReplace(native.FunctionARN, bindings) {
					t.Fatalf("marker %q invoked function %s, native %s", record.Probe, record.FunctionARN, native.FunctionARN)
				}
				want := gatewayClone(t, native.Event)
				gatewaySubstitute(want, bindings)
				gatewayCompareEvent(t, record.Event, want, bindings)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("only %d/%d expected backend invocation logs arrived", len(records), len(expected))
		case <-time.After(25 * time.Millisecond):
		}
	}
}
