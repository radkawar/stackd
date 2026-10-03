package stackd_test

import (
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
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type gatewayKeyRuntimeFixture struct {
	gatewayTimelineFixture
	HTTP                   []gatewayKeyRuntimeHTTP
	FreshAuthorizerCapture *gatewayKeyRuntimeFixture `json:"fresh_authorizer_capture"`
	PolicyRecoveryCapture  *gatewayKeyRuntimeFixture `json:"policy_recovery_capture"`
	MethodQuotaCapture     *gatewayKeyRuntimeFixture `json:"method_quota_capture"`
	QuotaCapture           *gatewayKeyRuntimeFixture `json:"quota_capture"`
	QuotaRecoveryCapture   *gatewayKeyRuntimeFixture `json:"quota_recovery_capture"`
	Logs                   []struct {
		Timestamp int64
		Record    gatewayKeyRuntimeLog
	} `json:"invocation_logs"`
	LogCollection struct {
		StableSnapshots int    `json:"stable_consecutive_snapshots"`
		AbsenceScope    string `json:"absence_scope"`
	} `json:"log_collection"`
	PolicySamples map[string]struct {
		Requests []struct{ Label, Path string }
	} `json:"policy_samples"`
}

type gatewayKeyRuntimeHTTP struct {
	restIntegrationCredentialsHTTP
	FinishedAt time.Time `json:"finished_at"`
}

type gatewayKeyRuntimeLog struct {
	ProbeKind                string `json:"probe_kind"`
	Invocation, Probe, Token string
	LambdaRequestID          string `json:"lambdaRequestId"`
	RequestContext           map[string]any
	Event, Response          map[string]any
}

type gatewayKeyRuntimeExpectedLog struct {
	Native  gatewayKeyRuntimeLog
	Headers map[string]string
}

func TestAPIGatewayAPIKeyRuntimeNative(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real API key authorizer and backend runtimes")
	}
	var native gatewayKeyRuntimeFixture
	awsReadFixture(t, "apigateway/api_key_runtime.json", &native)
	if native.FreshAuthorizerCapture == nil {
		t.Fatal("missing independent initial-AUTHORIZER capture")
	}
	captures := []struct {
		name string
		data *gatewayKeyRuntimeFixture
	}{{"lifecycle", &native}, {"fresh-authorizer", native.FreshAuthorizerCapture}}
	// An interrupted policy capture without bounded invocation logs cannot
	// establish backend noninvocation. Keep it documentary, not invented replay.
	for _, capture := range []struct {
		name string
		data *gatewayKeyRuntimeFixture
	}{{"policy-recovery", native.PolicyRecoveryCapture}, {"method-quota", native.MethodQuotaCapture}, {"quota", native.QuotaCapture}, {"quota-recovery", native.QuotaRecoveryCapture}} {
		if capture.data != nil && len(capture.data.Logs) != 0 {
			captures = append(captures, capture)
		} else {
			t.Logf("excluded %s: no completed owned-function invocation-log capture", capture.name)
		}
	}
	for _, capture := range captures {
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(capture.name+"/"+backend, func(t *testing.T) {
				replayGatewayKeyRuntime(t, *capture.data, backend)
			})
		}
	}
}

func replayGatewayKeyRuntime(t *testing.T, fixture gatewayKeyRuntimeFixture, backend string) {
	t.Helper()
	if len(fixture.Observations) == 0 || fixture.HandlerSource == "" || fixture.LogCollection.StableSnapshots < 2 {
		t.Fatal("native replay lacks controls, handler source or bounded stable log evidence")
	}
	source := clock.NewManual(fixture.Observations[0].StartedAt)
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	owner := gatewayNativeUser(t, clients, fixture.Account, fixture.Region, fixture.Identity.Arn)
	bindings := map[string]string{}
	apiID, functionName := "", ""
	nativeBackends := map[string]gatewayKeyRuntimeLog{}
	nativeBackendRequests := map[string]bool{}
	for _, entry := range fixture.Logs {
		if entry.Record.ProbeKind == "backend" {
			nativeBackends[entry.Record.Invocation] = entry.Record
			requestID, _ := entry.Record.RequestContext["requestId"].(string)
			nativeBackendRequests[requestID] = true
		}
	}
	backends := map[string]gatewayKeyRuntimeExpectedLog{}
	authorizers := map[string]gatewayKeyRuntimeExpectedLog{}
	authorizerOrigins := map[string]string{}
	authorizerIDs := map[string]string{}
	checkLogs := func() {
		t.Helper()
		gatewayKeyRuntimeLogs(t, logsClient(clients, fixture.Account), "/aws/lambda/"+functionName, backends, authorizers, authorizerIDs, bindings)
	}

	call := func(row gatewaySDKObservation) {
		t.Helper()
		if row.Actor.Arn != "" && row.Actor.Arn != fixture.Identity.Arn {
			t.Fatalf("%s has an unestablished native actor %s", row.Label, row.Actor.Arn)
		}
		input := gatewayClone(t, row.Input)
		gatewaySubstitute(input, bindings)
		if row.Operation == "CreateFunction" {
			input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": fixture.HandlerSource})}
		}
		wire := &awstest.WireClient{Client: clients.server.Client()}
		client := gatewaySDKClient(t, row.Service, aws.Config{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: owner, HTTPClient: wire, RetryMaxAttempts: 1})
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		out, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
		if wire.Status != row.Result.HTTPStatus {
			t.Fatalf("%s HTTP=%d native=%d: %v", row.Label, wire.Status, row.Result.HTTPStatus, err)
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

	// Policy observations supply a set of outcomes, not an AWS token-bucket
	// schedule. Replay a captured group as one local burst, comparing per-path
	// admission/rejection evidence rather than each native request's timing.
	groups := map[string]string{}
	policyWant := map[string]map[string]map[int]gatewayKeyRuntimeHTTP{}
	policyGot := map[string]map[string]map[int]int{}
	rows := map[string]gatewayKeyRuntimeHTTP{}
	for _, row := range fixture.HTTP {
		rows[row.Label] = row
	}
	for name, sample := range fixture.PolicySamples {
		for _, request := range sample.Requests {
			row, present := rows[request.Label]
			if !present || row.Phase != "policy-observation" || fixture.ReplayExclusions[row.Label] != "" {
				continue
			}
			groups[row.Label] = name
			if policyWant[name] == nil {
				policyWant[name] = map[string]map[int]gatewayKeyRuntimeHTTP{}
				policyGot[name] = map[string]map[int]int{}
			}
			if policyWant[name][row.Path] == nil {
				policyWant[name][row.Path] = map[int]gatewayKeyRuntimeHTTP{}
				policyGot[name][row.Path] = map[int]int{}
			}
			policyWant[name][row.Path][row.Result.Status] = row
		}
	}

	invoke := func(row gatewayKeyRuntimeHTTP, group string) {
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
			identity, err := owner.Retrieve(t.Context())
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
		wantRow := row
		if group != "" {
			var present bool
			wantRow, present = policyWant[group][row.Path][response.StatusCode]
			if !present {
				t.Fatalf("%s policy %s returned uncaptured status %d: %s", row.Label, group, response.StatusCode, body)
			}
			policyGot[group][row.Path][response.StatusCode]++
		} else if response.StatusCode != row.Result.Status {
			t.Fatalf("%s status=%d native=%d: %s", row.Label, response.StatusCode, row.Result.Status, body)
		}
		marker := request.Header.Get("X-Probe")
		if marker == "" {
			t.Fatalf("%s lacks the captured invocation marker", row.Label)
		}
		// A semantic cache hit can originate in a skipped readiness request.
		// Find its actual native authorizer record, rather than treating the
		// missing same-request log as evidence that authorization never ran.
		var nativeAuth gatewayKeyRuntimeLog
		var authAt int64
		for _, entry := range fixture.Logs {
			candidate := entry.Record
			if candidate.ProbeKind != "authorizer" || candidate.Token != request.Header.Get("X-Auth") || entry.Timestamp > row.FinishedAt.UnixMilli() || entry.Timestamp < authAt {
				continue
			}
			rc, _ := candidate.Event["requestContext"].(map[string]any)
			if rc["path"] == row.Path {
				nativeAuth, authAt = candidate, entry.Timestamp
			}
		}
		if nativeAuth.Invocation != "" {
			if _, seen := authorizerOrigins[nativeAuth.Invocation]; !seen {
				authorizerOrigins[nativeAuth.Invocation] = marker
				authorizers[marker] = gatewayKeyRuntimeExpectedLog{Native: nativeAuth, Headers: row.RequestHeaders}
			}
		}
		var actual map[string]any
		awsDecodeJSON(t, body, &actual)
		if response.StatusCode != http.StatusOK {
			if len(actual) != len(wantRow.Result.Body) {
				t.Fatalf("%s error envelope differs: %s", row.Label, body)
			}
			for name, expected := range wantRow.Result.Body {
				got, present := actual[name]
				if !present || reflect.TypeOf(got) != reflect.TypeOf(expected) {
					t.Fatalf("%s error field %s differs: %s", row.Label, name, body)
				}
			}
			nativeRequestID := ""
			for _, header := range wantRow.Result.Headers {
				if len(header) == 2 && strings.EqualFold(header[0], "x-amzn-ErrorType") && response.Header.Get(header[0]) != header[1] {
					t.Fatalf("%s error classification=%s native=%s", row.Label, response.Header.Get(header[0]), header[1])
				}
				if len(header) == 2 && strings.EqualFold(header[0], "x-amzn-RequestId") {
					nativeRequestID = header[1]
				}
			}
			// Readiness retries can reuse X-Probe. Only the gateway request ID
			// identifies the particular native denial whose absence we assert.
			if nativeRequestID == "" || nativeBackendRequests[nativeRequestID] {
				t.Fatalf("%s native denial lacks a request ID or has a backend invocation", wantRow.Label)
			}
			return
		}
		id, _ := actual["backendInvocationId"].(string)
		if _, exists := backends[id]; id == "" || exists {
			t.Fatalf("%s did not execute a distinct real backend: %v", row.Label, actual)
		}
		nativeID, _ := wantRow.Result.Body["backendInvocationId"].(string)
		nativeLog, present := nativeBackends[nativeID]
		if !present || nativeLog.Probe != wantRow.RequestHeaders["X-Probe"] {
			t.Fatalf("%s accepted native HTTP outcome has no matching backend log", wantRow.Label)
		}
		got, ok := actual["event"].(map[string]any)
		if !ok {
			t.Fatalf("%s missing real backend event", row.Label)
		}
		want := gatewayClone(t, wantRow.Result.Body["event"].(map[string]any))
		gatewaySubstitute(want, bindings)
		restIntegrationCredentialFields(t, row.Label, got, want, "resource", "path", "httpMethod", "stageVariables")
		gotContext := got["requestContext"].(map[string]any)
		gatewayKeyRuntimeContext(t, row.Label, gotContext, want["requestContext"].(map[string]any), authorizerIDs)
		nativeLog.Probe = marker
		backends[id] = gatewayKeyRuntimeExpectedLog{Native: nativeLog}
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
	controls, httpCalls, reopens := 0, 0, 0
	pendingReopen := false
	activeGroup := ""
	excluded := map[string]int{}
	for _, next := range steps {
		group := ""
		if next.http {
			row := fixture.HTTP[next.index]
			if reason := fixture.ReplayExclusions[row.Label]; reason != "" {
				t.Logf("excluded HTTP %s: %s", row.Label, reason)
				continue
			}
			group = groups[row.Label]
			if row.Phase != "semantic" && group == "" {
				excluded["HTTP "+row.Phase]++
				continue
			}
		} else {
			row := fixture.Observations[next.index]
			if reason := fixture.ReplayExclusions[row.Label]; reason != "" {
				t.Logf("excluded control %s: %s", row.Label, reason)
				continue
			}
			switch {
			case row.Phase == "cleanup" || strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "absence-"):
				excluded["cleanup and absence checks"]++
				continue
			case row.Service == "logs" && row.Operation != "CreateLogGroup":
				excluded["native log collection controls"]++
				continue
			case row.Phase == "readiness" && row.Result.Code != "Success":
				excluded["classified readiness/role propagation controls"]++
				continue
			}
		}
		if (group == "" || group != activeGroup) && next.at.After(source.Now()) {
			source.Advance(next.at.Sub(source.Now()))
		}
		activeGroup = group
		if !next.http {
			row := fixture.Observations[next.index]
			call(row)
			controls++
			if row.Result.Code == "Success" {
				switch row.Operation {
				case "CreateUsagePlanKey", "DeleteUsagePlanKey", "UpdateApiKey", "DeleteApiKey", "UpdateUsagePlan", "UpdateMethod", "CreateDeployment", "FlushStageAuthorizersCache":
					pendingReopen = true
				}
			}
			continue
		}
		row := fixture.HTTP[next.index]
		if pendingReopen {
			checkLogs()
			clients = reopen()
			pendingReopen = false
			reopens++
		}
		invoke(row, group)
		httpCalls++
		// Reopen between a native cache origin and its next request. This also
		// tests retained rejected usage keys, not just successful cache entries.
		if row.RequestHeaders["X-Auth"] != "" {
			pendingReopen = true
		}
	}
	checkLogs()
	for group, paths := range policyWant {
		accepted := 0
		nativeAccepted := false
		for path, outcomes := range paths {
			accepted += policyGot[group][path][http.StatusOK]
			_, hasSuccess := outcomes[http.StatusOK]
			nativeAccepted = nativeAccepted || hasSuccess
			if _, throttled := outcomes[http.StatusTooManyRequests]; throttled {
				if policyGot[group][path][http.StatusTooManyRequests] == 0 {
					t.Fatalf("%s %s burst lost native throttling: %v", group, path, policyGot[group][path])
				}
			} else if policyGot[group][path][http.StatusOK] == 0 {
				t.Fatalf("%s %s burst lost native unrestricted admission", group, path)
			}
		}
		// A shared plan can give its one burst token to either captured route.
		// Native refill timing does not require every route to win that token.
		if nativeAccepted && accepted == 0 {
			t.Fatalf("%s rejected the entire burst despite native admissions", group)
		}
	}
	if reopens == 0 {
		t.Fatal("no retained key/plan/deployment/cache boundary was exercised")
	}
	t.Logf("replayed %d SDK controls, %d HTTP requests and %d retained-state reopen boundaries; excluded %v; policy groups compare outcome classes, not AWS timing; native noninvocation scope: %s", controls, httpCalls, reopens, excluded, fixture.LogCollection.AbsenceScope)
}

func gatewayKeyRuntimeContext(t *testing.T, label string, got, want map[string]any, authorizerIDs map[string]string) {
	t.Helper()
	restIntegrationCredentialFields(t, label, got, want, "resourcePath", "httpMethod", "path", "stage")
	gotIdentity, _ := got["identity"].(map[string]any)
	wantIdentity, _ := want["identity"].(map[string]any)
	// Field absence is evidence too: AUTHORIZER optional methods omit both,
	// while HEADER captures can expose a supplied value without an admitted ID.
	restIntegrationCredentialFields(t, label+" identity", gotIdentity, wantIdentity, "apiKey", "apiKeyId")
	gotAuth, gotPresent := got["authorizer"].(map[string]any)
	wantAuth, wantPresent := want["authorizer"].(map[string]any)
	if gotPresent != wantPresent {
		t.Fatalf("%s authorizer context presence differs", label)
	}
	if !wantPresent {
		return
	}
	restIntegrationCredentialFields(t, label+" authorizer", gotAuth, wantAuth, "principalId", "token")
	nativeID, _ := wantAuth["invocation"].(string)
	actualID, _ := gotAuth["invocation"].(string)
	if nativeID == "" || actualID == "" {
		t.Fatalf("%s lacks real authorizer invocation identity", label)
	}
	if previous := authorizerIDs[nativeID]; previous != "" && previous != actualID {
		t.Fatalf("%s lost the cached native authorizer result", label)
	}
	for previous, actual := range authorizerIDs {
		if previous != nativeID && actual == actualID {
			t.Fatalf("%s reused an authorizer result across distinct native invocations", label)
		}
	}
	authorizerIDs[nativeID] = actualID
}

func gatewayKeyRuntimeLogs(t *testing.T, client *cloudwatchlogs.Client, group string, backends, authorizers map[string]gatewayKeyRuntimeExpectedLog, authorizerIDs, bindings map[string]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for {
		seen := map[string]bool{}
		requests := map[string]bool{}
		for _, message := range gatewayLogMessages(t, ctx, client, group, `"probe_kind"`) {
			var record gatewayKeyRuntimeLog
			if json.Unmarshal([]byte(strings.TrimSpace(message)), &record) != nil || record.ProbeKind == "" {
				continue
			}
			if record.Invocation == "" || seen[record.Invocation] || record.LambdaRequestID == "" || requests[record.LambdaRequestID] {
				t.Fatalf("Lambda log has missing or reused invocation/request identity: %+v", record)
			}
			seen[record.Invocation], requests[record.LambdaRequestID] = true, true
			switch record.ProbeKind {
			case "backend":
				expected, ok := backends[record.Invocation]
				if !ok || expected.Native.Probe != record.Probe {
					t.Fatalf("unexpected backend invocation, including a denied request: %+v", record)
				}
				want := gatewayClone(t, expected.Native.RequestContext)
				gatewaySubstitute(want, bindings)
				gatewayKeyRuntimeContext(t, record.Probe+" backend log", record.RequestContext, want, authorizerIDs)
			case "authorizer":
				expected, ok := authorizers[record.Probe]
				if !ok {
					t.Fatalf("unexpected authorizer invocation (including a cache hit): %+v", record)
				}
				native := expected.Native
				if id := authorizerIDs[native.Invocation]; id != "" && id != record.Invocation {
					t.Fatalf("%s authorizer log and backend cache identity disagree", record.Probe)
				}
				authorizerIDs[native.Invocation] = record.Invocation
				want := gatewayClone(t, native.Response)
				gatewaySubstitute(want, bindings)
				restIntegrationCredentialFields(t, record.Probe+" authorizer response", record.Response, want, "principalId", "policyDocument", "usageIdentifierKey")
				wantEvent := gatewayClone(t, native.Event)
				gatewaySubstitute(wantEvent, bindings)
				restIntegrationCredentialFields(t, record.Probe+" authorizer event", record.Event, wantEvent, "type", "methodArn", "resource", "path", "httpMethod")
				for _, name := range []string{"X-Auth", "X-Usage-Key"} {
					header := ""
					for key, value := range record.Event["headers"].(map[string]any) {
						if strings.EqualFold(key, name) {
							header, _ = value.(string)
						}
					}
					if want := gatewayReplace(expected.Headers[name], bindings); header != want {
						t.Fatalf("%s authorizer header %s=%q native selected request=%q", record.Probe, name, header, want)
					}
				}
			default:
				t.Fatalf("unexpected native probe kind %q", record.ProbeKind)
			}
		}
		if len(seen) == len(backends)+len(authorizers) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("only %d/%d backend and authorizer log witnesses arrived", len(seen), len(backends)+len(authorizers))
		case <-time.After(25 * time.Millisecond):
		}
	}
}
