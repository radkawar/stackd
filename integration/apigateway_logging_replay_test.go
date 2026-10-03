package stackd_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"stackd"
	"stackd/internal/awstest"
)

type gatewayLoggingEvent struct {
	Group, Message, EventID string
}

type gatewayLoggingCorrelation struct {
	Protocol, Label, Marker string
	RequestID               string   `json:"request_id"`
	AccessEventIDs          []string `json:"access_event_ids"`
	ExecutionEventIDs       []string `json:"execution_event_ids"`
	LambdaEventIDs          []string `json:"lambda_event_ids"`
	LambdaEventID           string   `json:"lambda_event_id"`
}

type gatewayLoggingFixture struct {
	gatewayTimelineFixture
	Owned               map[string]any
	LogEvents           map[string]gatewayLoggingEvent   `json:"log_events"`
	RawLogs             map[string][]gatewayLoggingEvent `json:"raw_logs"`
	RequestCorrelations map[string]struct {
		AccessEventKeys []string `json:"access_event_keys"`
		LambdaEventKeys []string `json:"lambda_event_keys"`
	} `json:"request_correlations"`
	Correlations []gatewayLoggingCorrelation
	Sockets      []gatewayMetricSocket `json:"websocket_observations"`
}

type gatewayLoggingReplay struct {
	t           *testing.T
	fixture     gatewayLoggingFixture
	clients     cloudClients
	reopen      func() cloudClients
	owner       credentials.StaticCredentialsProvider
	actors      map[string]aws.CredentialsProvider
	bindings    map[string]string
	bodyLengths map[string]int
	contexts    map[string]map[string]any
}

func newGatewayLoggingReplay(t *testing.T, fixture gatewayLoggingFixture, backend string) *gatewayLoggingReplay {
	t.Helper()
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	owner := gatewayNativeUser(t, clients, fixture.Account, fixture.Region, fixture.Identity.Arn)
	r := &gatewayLoggingReplay{t: t, fixture: fixture, clients: clients, reopen: reopen, owner: owner,
		actors: map[string]aws.CredentialsProvider{fixture.Identity.Arn: owner}, bindings: map[string]string{}, bodyLengths: map[string]int{}, contexts: map[string]map[string]any{}}
	return r
}

func (r *gatewayLoggingReplay) config(actor aws.CredentialsProvider) aws.Config {
	return aws.Config{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: actor, HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1}
}

func (r *gatewayLoggingReplay) row(label string) gatewaySDKObservation {
	r.t.Helper()
	for _, row := range r.fixture.Observations {
		if row.Label == label {
			return row
		}
	}
	r.t.Fatalf("missing native logging observation %s", label)
	return gatewaySDKObservation{}
}

func (r *gatewayLoggingReplay) call(row gatewaySDKObservation) map[string]any {
	t := r.t
	t.Helper()
	actor := r.actors[row.Actor.Arn]
	if row.Actor.Arn == "" {
		actor = r.owner
	}
	if actor == nil {
		t.Fatalf("%s uses unestablished actor %s", row.Label, row.Actor.Arn)
	}
	input := gatewayClone(t, row.Input)
	gatewaySubstitute(input, r.bindings)
	if row.Operation == "CreateFunction" {
		input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": r.fixture.HandlerSource})}
	}
	config := r.config(actor)
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	config.HTTPClient = wire
	client := gatewaySDKClient(t, row.Service, config)
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
		return nil
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
	if row.Operation == "GetStage" || row.Operation == "UpdateStage" || row.Operation == "GetAccount" {
		var controls map[string]any
		awsDecodeJSON(t, wire.Body, &controls)
		want := gatewayClone(t, row.Result.Output)
		gatewaySubstitute(want, r.bindings)
		if got, expected := gatewayLoggingSettings(controls), gatewayLoggingSettings(want); !reflect.DeepEqual(got, expected) {
			t.Fatalf("%s retained logging settings=%v native=%v", row.Label, got, expected)
		}
	}
	gatewayBind(row.Result.Output, actual, r.bindings)
	if assumed, ok := out.(*sts.AssumeRoleOutput); ok {
		native := row.Result.Output["AssumedRoleUser"].(map[string]any)["Arn"].(string)
		r.actors[native] = credentials.NewStaticCredentialsProvider(*assumed.Credentials.AccessKeyId, *assumed.Credentials.SecretAccessKey, *assumed.Credentials.SessionToken)
	}
	if row.Operation == "CreateFunction" {
		name := actual["FunctionName"].(string)
		if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
			t.Fatal(err)
		}
	}
	return actual
}

// Only retained logging controls are compared: dates, default throttles and
// unrelated metric settings are not the behavioral contract under replay.
func gatewayLoggingSettings(value map[string]any) map[string]any {
	out := map[string]any{}
	var visit func(map[string]any, string)
	visit = func(object map[string]any, path string) {
		for key, child := range object {
			name := strings.ToLower(key)
			switch name {
			case "accesslogsettings":
				if nested, ok := child.(map[string]any); ok {
					for field, value := range nested {
						out[path+"/"+name+"/"+strings.ToLower(field)] = value
					}
				}
			case "cloudwatchrolearn", "logginglevel", "datatraceenabled":
				if child != nil {
					out[path+"/"+name] = child
				}
			default:
				if nested, ok := child.(map[string]any); ok {
					visit(nested, path+"/"+name)
				}
			}
		}
	}
	visit(value, "")
	return out
}

func (r *gatewayLoggingReplay) logs() *cloudwatchlogs.Client {
	return cloudwatchlogs.NewFromConfig(r.config(r.owner))
}

func (r *gatewayLoggingReplay) localURL(native string, socket bool) string {
	// Reuse the native Gateway endpoint translator, not a handler invocation.
	return (&gatewayMetricReplay{t: r.t, clients: r.clients, bindings: r.bindings}).localURL(native, socket)
}

func (r *gatewayLoggingReplay) http(index int) {
	t := r.t
	t.Helper()
	row := r.fixture.HTTP[index]
	api := r.fixture.Owned[row.API+"_api"].(string)
	endpoint := "https://" + api + ".execute-api." + r.fixture.Region + ".amazonaws.com" + row.Path
	request, err := http.NewRequestWithContext(t.Context(), row.Method, r.localURL(endpoint, false), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range row.RequestHeaders {
		request.Header.Set(name, value)
	}
	if len(row.RequestHeaders) == 0 {
		request.Header.Set("User-Agent", "stackd-native-gateway-probe")
		request.Header.Set("X-Probe", row.Label)
	}
	request.Header.Set("Accept-Encoding", "identity")
	if strings.HasSuffix(row.Label, "-signed") || strings.HasSuffix(row.Label, "-allowed") {
		creds, err := r.owner.Retrieve(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(nil)
		if err := v4.NewSigner().SignHTTP(t.Context(), creds, request, hex.EncodeToString(digest[:]), "execute-api", r.fixture.Region, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	response, err := r.clients.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != row.Result.Status {
		t.Fatalf("%s HTTP=%d native=%d: %s", row.Label, response.StatusCode, row.Result.Status, body)
	}
	for _, pair := range row.Result.Headers {
		if len(pair) != 2 {
			continue
		}
		switch strings.ToLower(pair[0]) {
		case "apigw-requestid", "x-amzn-requestid", "x-amz-apigw-id":
			value := response.Header.Get(pair[0])
			if value == "" {
				t.Fatalf("%s missing %s", row.Label, pair[0])
			}
			r.bindings[pair[1]] = value
			r.bodyLengths[value] = len(body)
		}
	}
	var actual map[string]any
	awsDecodeJSON(t, body, &actual)
	if message, ok := row.Result.Body["message"]; ok && actual["message"] != message {
		t.Fatalf("%s error body=%s native=%v", row.Label, body, message)
	}
	for _, key := range []string{"marker", "mode", "probe_kind", "status"} {
		if expected, ok := row.Result.Body[key]; ok && actual[key] != expected {
			t.Fatalf("%s %s=%v native=%v", row.Label, key, actual[key], expected)
		}
	}
	for _, key := range []string{"request_id", "lambda_request_id", "invocation"} {
		if native, ok := row.Result.Body[key].(string); ok {
			local, _ := actual[key].(string)
			if local == "" {
				t.Fatalf("%s missing runtime %s", row.Label, key)
			}
			if bound, ok := r.bindings[native]; ok && bound != local {
				t.Fatalf("%s %s disagrees with response request ID", row.Label, key)
			}
			r.bindings[native] = local
		}
	}
}

func (r *gatewayLoggingReplay) awaitMessages(group string, ready func([]string) bool) []string {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(r.t.Context(), 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var messages []string
	for {
		messages = gatewayLogMessages(r.t, ctx, r.logs(), gatewayReplace(group, r.bindings), "")
		if ready(messages) {
			return messages
		}
		select {
		case <-ctx.Done():
			r.t.Fatalf("logging witness missing in %s: %v", group, messages)
		case <-ticker.C:
		}
	}
}

func (r *gatewayLoggingReplay) application(native gatewayLoggingEvent) {
	t := r.t
	t.Helper()
	var expected map[string]any
	awsDecodeJSON(t, []byte(native.Message), &expected)
	nativeContext := expected["event"].(map[string]any)["requestContext"].(map[string]any)
	var actual map[string]any
	r.awaitMessages("/aws/lambda/"+r.fixture.Owned["function"].(string), func(messages []string) bool {
		for _, message := range messages {
			var record map[string]any
			if json.Unmarshal([]byte(message), &record) != nil || record["probe_kind"] != expected["probe_kind"] {
				continue
			}
			if marker, ok := expected["marker"]; ok {
				if record["marker"] != marker {
					continue
				}
			} else {
				if record["event"] == nil {
					continue
				}
				context := record["event"].(map[string]any)["requestContext"].(map[string]any)
				if context["requestId"] != r.bindings[nativeContext["requestId"].(string)] {
					continue
				}
			}
			actual = record
			return true
		}
		return false
	})
	localContext := actual["event"].(map[string]any)["requestContext"].(map[string]any)
	r.contexts[localContext["requestId"].(string)] = localContext
	for _, key := range []string{"requestId", "extendedRequestId", "connectionId", "messageId"} {
		before, ok := nativeContext[key].(string)
		if !ok || before == "" {
			continue
		}
		after, _ := localContext[key].(string)
		if after == "" {
			t.Fatalf("runtime lacks %s: %v", key, actual)
		}
		if bound, ok := r.bindings[before]; ok && bound != after {
			t.Fatalf("runtime %s=%s disagrees with bound %s", key, after, bound)
		}
		r.bindings[before] = after
	}
	for _, key := range []string{"invocation", "invocation_id"} {
		if before, ok := expected[key].(string); ok {
			after, _ := actual[key].(string)
			if len(after) != 36 {
				t.Fatalf("runtime invocation is not a Lambda request UUID: %v", actual)
			}
			if bound, ok := r.bindings[before]; ok && bound != after {
				t.Fatalf("Lambda application log disagrees with client invocation %s", bound)
			}
			r.bindings[before] = after
		}
	}
	for _, key := range []string{"routeKey", "eventType", "resourcePath", "httpMethod"} {
		if want, ok := nativeContext[key]; ok && localContext[key] != want {
			t.Fatalf("runtime %s=%v native=%v", key, localContext[key], want)
		}
	}
	if actual["runtime"] == nil {
		t.Fatalf("application lacks actual runtime witness: %v", actual)
	}
}

func gatewayLoggingFields(message string) map[string]string {
	fields := map[string]string{}
	if strings.HasPrefix(message, "{") {
		if json.Unmarshal([]byte(message), &fields) != nil {
			return nil
		}
		return fields
	}
	for _, part := range strings.Split(message, "|") {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			fields[key] = value
		}
	}
	return fields
}

func (r *gatewayLoggingReplay) access(group string, native gatewayLoggingEvent) {
	t := r.t
	t.Helper()
	want := gatewayLoggingFields(native.Message)
	id := r.bindings[want["requestId"]]
	if id == "" {
		t.Fatalf("access record lacks client/runtime request correlation: %s", native.Message)
	}
	var got map[string]string
	r.awaitMessages(group, func(messages []string) bool {
		for _, message := range messages {
			fields := gatewayLoggingFields(message)
			if fields["requestId"] == id {
				got = fields
				return true
			}
		}
		return false
	})
	for key, expected := range want {
		actual, present := got[key]
		if !present {
			t.Fatalf("access request %s missing %s", id, key)
		}
		if expected == "-" {
			if actual != "-" {
				t.Fatalf("access %s %s=%q native absent", id, key, actual)
			}
			continue
		}
		switch key {
		case "domainName", "domainPrefix":
			// The replay's HTTP endpoint override changes the inbound host,
			// not the API's identity in ARNs and route bindings.
			domain := strings.TrimPrefix(r.clients.server.URL, "http://")
			if key == "domainPrefix" {
				domain, _, _ = strings.Cut(domain, ".")
			}
			if actual != domain {
				t.Fatalf("access %s=%q request host implies %q", key, actual, domain)
			}
		case "requestTime":
			if _, err := time.Parse("02/Jan/2006:15:04:05 -0700", actual); err != nil {
				t.Fatalf("access time %q: %v", actual, err)
			}
			if context := r.contexts[id]; context != nil {
				backend := context["requestTime"]
				if backend == nil {
					backend = context["time"]
				}
				if actual != backend {
					t.Fatalf("access time=%q differs from runtime event %v", actual, backend)
				}
			}
		case "requestTimeEpoch":
			n, err := strconv.ParseInt(actual, 10, 64)
			if err != nil || (len(expected) == 10 && len(actual) != 10) || (len(expected) == 13 && len(actual) != 13) || n <= 0 {
				t.Fatalf("access epoch=%q native units=%q", actual, expected)
			}
			if context := r.contexts[id]; context != nil {
				epoch, ok := context["requestTimeEpoch"].(float64)
				if !ok {
					epoch, ok = context["timeEpoch"].(float64)
				}
				backend := int64(epoch)
				if len(expected) == 10 {
					backend /= 1000
				}
				if !ok || n != backend {
					t.Fatalf("access epoch=%d differs from runtime event %v", n, context)
				}
			}
		case "responseLatency", "integrationLatency", "integration.latency", "dataProcessed", "connectedAt":
			// The native denial byte total includes inbound request bytes, but
			// that formula is unproven. Do not invent parity for this field.
			if key == "dataProcessed" && want["integration.requestId"] == "-" {
				continue
			}
			if n, err := strconv.ParseInt(actual, 10, 64); err != nil || n < 0 {
				t.Fatalf("access %s is not nonnegative: %q", key, actual)
			}
		case "responseLength":
			if length, ok := r.bodyLengths[id]; !ok || actual != strconv.Itoa(length) {
				t.Fatalf("access length=%s client bytes=%d (known=%v)", actual, length, ok)
			}
		case "identity.sourceIp":
			if net.ParseIP(actual) == nil {
				t.Fatalf("invalid access source IP %q", actual)
			}
		case "identity.caller", "identity.user":
			user, err := iam.NewFromConfig(r.config(r.owner)).GetUser(t.Context(), &iam.GetUserInput{})
			if err != nil || actual != aws.ToString(user.User.UserId) {
				t.Fatalf("access signed identity %s=%s user=%v error=%v", key, actual, user, err)
			}
		default:
			if actual != gatewayReplace(expected, r.bindings) {
				t.Fatalf("access %s %s=%q native=%q", id, key, actual, gatewayReplace(expected, r.bindings))
			}
		}
	}
}

func (r *gatewayLoggingReplay) retain(groups []string, controls []gatewaySDKObservation) {
	r.t.Helper()
	before := map[string][]string{}
	for _, group := range groups {
		messages := gatewayLogMessages(r.t, r.t.Context(), r.logs(), gatewayReplace(group, r.bindings), "")
		sort.Strings(messages)
		before[group] = messages
	}
	r.clients = r.reopen()
	for _, row := range controls {
		r.call(row)
	}
	for group, expected := range before {
		actual := gatewayLogMessages(r.t, r.t.Context(), r.logs(), gatewayReplace(group, r.bindings), "")
		sort.Strings(actual)
		if !reflect.DeepEqual(actual, expected) {
			r.t.Fatalf("retained log history changed for %s", group)
		}
	}
}
