package stackd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"stackd/storage"
)

func (r *lambdaURLReplay) httpClient() *http.Client {
	// Dial only changes transport routing. The advertised URL, signed host and
	// private routing prefix remain intact, just as they do for a real caller.
	local, _ := url.Parse(r.c.server.URL)
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, local.Host)
	}}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (r *lambdaURLReplay) request(t *testing.T, endpoint, path, method string, headers [][2]string, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, strings.TrimSuffix(endpoint, "/")+"/"+strings.TrimPrefix(path, "/"), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range headers {
		if strings.EqualFold(pair[0], "host") {
			continue
		}
		if strings.EqualFold(pair[0], "user-agent") {
			request.Header.Set("User-Agent", pair[1])
			continue
		}
		// Preserve distinct wire header spellings, including captured duplicates.
		request.Header[pair[0]] = append(request.Header[pair[0]], pair[1])
	}
	return request
}
func lambdaURLSign(t *testing.T, request *http.Request, body []byte, key aws.Credentials) {
	t.Helper()
	digest := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(t.Context(), key, request, hex.EncodeToString(digest[:]), "lambda", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
}
func lambdaURLBody(t *testing.T, actual, expected []byte) {
	t.Helper()
	var got, want any
	if json.Unmarshal(actual, &got) == nil && json.Unmarshal(expected, &want) == nil {
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("JSON response got %s want %s", actual, expected)
		}
	} else if !bytes.Equal(actual, expected) {
		t.Fatalf("response bytes got %q want %q", actual, expected)
	}
}

// Compare the public error document's shape, not AWS's explanatory prose.
func lambdaURLForbidden(t *testing.T, actual, expected []byte) {
	t.Helper()
	var got, want map[string]any
	if err := json.Unmarshal(actual, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	if _, descriptive := want["Message"].(string); descriptive {
		if _, ok := got["Message"].(string); !ok {
			t.Fatalf("forbidden response lost its Message string: %s", actual)
		}
		delete(got, "Message")
		delete(want, "Message")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("forbidden response got %s native %s", actual, expected)
	}
}
func lambdaURLEvent(t *testing.T, actual, expected map[string]any) {
	t.Helper()
	// Do not normalize customer path/query/body/cookie values or their presence.
	// Only deployment and transport-generated identities differ from native AWS.
	clean := func(event map[string]any) {
		headers, _ := event["headers"].(map[string]any)
		for _, key := range []string{"host", "x-amzn-tls-version", "x-amzn-tls-cipher-suite", "x-amzn-trace-id", "x-forwarded-proto", "x-forwarded-port", "x-amz-date"} {
			delete(headers, key)
		}
		if headers["x-forwarded-for"] != "192.0.2.1" {
			delete(headers, "x-forwarded-for")
		}
		rc, _ := event["requestContext"].(map[string]any)
		for _, key := range []string{"apiId", "domainName", "domainPrefix", "requestId", "time", "timeEpoch"} {
			delete(rc, key)
		}
		h, _ := rc["http"].(map[string]any)
		delete(h, "sourceIp")
		if authorizer, ok := rc["authorizer"].(map[string]any); ok {
			if iam, ok := authorizer["iam"].(map[string]any); ok {
				delete(iam, "principalOrgId")
			}
		}
	}
	clean(actual)
	clean(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("customer URL event differs:\ngot %s\nwant %s", lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
	}
}

type lambdaURLHTTPCase struct {
	Label, Token  string
	Configuration struct {
		Function struct{ Handler string }
		URL      struct {
			AuthType   lambdatypes.FunctionUrlAuthType
			InvokeMode lambdatypes.InvokeMode
			Cors       *lambdatypes.Cors
		}
	}
	Request struct {
		Method    string
		PathQuery string `json:"path_query"`
		Headers   [][2]string
		Body      string `json:"body_base64"`
	}
	Response struct {
		Status            int
		Headers, Trailers [][2]string
		Body              string `json:"body_base64"`
	}
	TransportError    *struct{ Type string } `json:"transport_error"`
	ExecutionObserved bool                   `json:"execution_observed"`
	Event             map[string]any         `json:"lambda_event"`
	RequestID         string                 `json:"lambda_request_id"`
}

func TestLambdaURLsDockerHTTPNativeReplay(t *testing.T) {
	lambdaURLDocker(t)
	r := newLambdaURLReplay(t, "urls_http", storage.NewMemory(), nil)
	for _, row := range r.fixture.Observations {
		if row.Operation == "update_function_url_config" || row.Operation == "update_function_configuration" || row.Operation == "filter_log_events" {
			t.Logf("native setup/polling record %s: replayed through each HTTP case's retained configuration and real log reader", row.Label)
		}
	}
	for _, row := range r.fixture.Observations {
		if row.Label == "set_cors" {
			break
		}
		r.command(t, row)
	}
	var endpoint string
	for _, u := range r.urls {
		endpoint = u
	}
	if endpoint == "" {
		t.Fatal("native HTTP setup has no URL")
	}
	currentHandler := "entry.plain"
	currentMode := lambdatypes.InvokeModeBuffered
	var currentCors *lambdatypes.Cors
	for _, raw := range r.fixture.HTTPCases {
		var h lambdaURLHTTPCase
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(h.Label, "settle_") || strings.HasPrefix(h.Label, "warmup_") {
			t.Logf("native HTTP setup/propagation polling record: %s", h.Label)
			continue
		}
		if !t.Run(h.Label, func(t *testing.T) {
			if h.Label == "mapping_encoded" {
				t.Skip("native mixed-case repeated headers require raw spelling provenance erased by Go net/http; retained fixture is unchanged (documented transport limitation)")
			}
			if currentHandler != h.Configuration.Function.Handler {
				if _, err := r.c.lambda.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: &r.fixture.Prefix, Handler: &h.Configuration.Function.Handler}); err != nil {
					t.Fatal(err)
				}
				r.ready(t)
				currentHandler = h.Configuration.Function.Handler
			}
			config := h.Configuration.URL
			if currentMode != config.InvokeMode || !reflect.DeepEqual(currentCors, config.Cors) {
				cors := config.Cors
				if cors == nil {
					cors = &lambdatypes.Cors{}
				}
				if _, err := r.c.lambda.UpdateFunctionUrlConfig(t.Context(), &awslambda.UpdateFunctionUrlConfigInput{FunctionName: &r.fixture.Prefix, AuthType: config.AuthType, InvokeMode: config.InvokeMode, Cors: cors}); err != nil {
					t.Fatal(err)
				}
				currentMode, currentCors = config.InvokeMode, config.Cors
			}
			advanceClock(t, r.clock, time.Minute)
			r.httpReplay(t, endpoint, h)
		}) {
			t.FailNow()
		}
	}
}
func (r *lambdaURLReplay) httpReplay(t *testing.T, endpoint string, h lambdaURLHTTPCase) {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(h.Request.Body)
	if err != nil {
		t.Fatal(err)
	}
	request := r.request(t, endpoint, h.Request.PathQuery, h.Request.Method, h.Request.Headers, body)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request = request.WithContext(ctx)
	client := r.httpClient()
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != h.Response.Status {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("HTTP %d want %d: %q", response.StatusCode, h.Response.Status, data)
	}
	lambdaURLHeaders(t, response.Header, h.Response.Headers)
	expected, err := base64.StdEncoding.DecodeString(h.Response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if h.TransportError != nil {
		// Native captured headers followed by read timeouts at 18 and 90 seconds.
		// Observe the same no-clean-EOF state locally without claiming an AWS limit.
		timer := time.AfterFunc(350*time.Millisecond, cancel)
		defer timer.Stop()
		actual, readErr := io.ReadAll(response.Body)
		if readErr == nil || !errors.Is(ctx.Err(), context.Canceled) || len(actual) != 0 {
			t.Fatalf("empty streaming response must stay pending until client cancellation: body=%q err=%v context=%v", actual, readErr, ctx.Err())
		}
	} else if h.Label == "stream_disconnect" {
		prefix := make([]byte, 4)
		if _, err := io.ReadFull(response.Body, prefix); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(prefix, expected) {
			t.Fatalf("first streaming bytes got %q want %q", prefix, expected)
		}
		cancel()
		response.Body.Close()
		// Completion in the customer logs below proves disconnect does not cancel
		// the Lambda invocation, including its delayed second write.
	} else {
		var actual []byte
		if h.Label == "stream_metadata" || h.Label == "stream_no_metadata" {
			first := make([]byte, 4)
			if _, err := io.ReadFull(response.Body, first); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			rest, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(started) < 50*time.Millisecond {
				t.Fatal("streaming first bytes were buffered until the delayed final write")
			}
			actual = append(first, rest...)
		} else {
			actual, err = io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
		}
		// Correlate both ordinary echo output and the stream suffix with the actual
		// HTTP request ID; all remaining response bytes are native customer output.
		if h.RequestID != "" {
			expected = bytes.ReplaceAll(expected, []byte(h.RequestID), []byte(response.Header.Get("x-amzn-requestid")))
		}
		if h.Event != nil && (strings.HasPrefix(h.Label, "mapping_") || h.Label == "cors_match" || h.Label == "cors_nonmatch" || h.Label == "cors_no_origin") && h.Request.Method != "HEAD" {
			var got, want map[string]any
			if err := json.Unmarshal(actual, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(expected, &want); err != nil {
				t.Fatal(err)
			}
			lambdaURLEvent(t, got["event"].(map[string]any), want["event"].(map[string]any))
			delete(got, "event")
			delete(want, "event")
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("echo response got %v want %v", got, want)
			}
		} else {
			lambdaURLBody(t, actual, expected)
		}
		lambdaURLHeaders(t, response.Trailer, h.Response.Trailers)
	}
	event, records := r.runtimeURLRecords(t, h.Token, h.ExecutionObserved, h.Label == "stream_disconnect")
	if h.ExecutionObserved {
		if event == nil {
			t.Fatalf("HTTP response had no executed customer event: %v", records)
		}
		if event["requestContext"].(map[string]any)["requestId"] != response.Header.Get("x-amzn-requestid") {
			t.Fatal("HTTP and runtime event request IDs differ")
		}
		lambdaURLEvent(t, event, h.Event)
	} else if event != nil {
		t.Fatalf("native preflight bypasses invocation but customer executed: %v", records)
	}
}
func lambdaURLHeaders(t *testing.T, actual http.Header, pairs [][2]string) {
	t.Helper()
	expected := http.Header{}
	for _, p := range pairs {
		expected.Add(p[0], p[1])
	}
	// Preserve header values, multiplicity and absence for customer-visible
	// response metadata. Date, trace IDs, host-dependent lengths and framing are
	// checked separately from this stable semantic header projection.
	keys := []string{"Content-Type", "Set-Cookie", "X-Owned", "X-Amzn-Errortype", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Max-Age", "Vary"}
	for _, key := range keys {
		if !reflect.DeepEqual(actual.Values(key), expected.Values(key)) {
			t.Fatalf("header %s got %q want %q", key, actual.Values(key), expected.Values(key))
		}
	}
}
func (r *lambdaURLReplay) runtimeURLRecords(t *testing.T, token string, executed, continued bool) (map[string]any, []string) {
	t.Helper()
	client := logsClient(cloudClients{r.c.server}, "test")
	deadline := time.Now().Add(10 * time.Second)
	if !executed {
		deadline = time.Now().Add(250 * time.Millisecond)
	}
	var event map[string]any
	var messages []string
	for {
		result, err := client.FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + r.fixture.Prefix), FilterPattern: aws.String(`"` + token + `"`)})
		if err != nil {
			t.Fatal(err)
		}
		event = nil
		messages = nil
		complete := false
		writes := 0
		for _, record := range result.Events {
			message := aws.ToString(record.Message)
			if !strings.Contains(message, token) {
				continue
			}
			messages = append(messages, message)
			if i := strings.Index(message, "URL_EVENT "); i >= 0 {
				var record struct{ Event map[string]any }
				if err := json.Unmarshal([]byte(strings.TrimSpace(message[i+len("URL_EVENT "):])), &record); err != nil {
					t.Fatal(err)
				}
				event = record.Event
			}
			complete = complete || strings.Contains(message, "URL_COMPLETE ") || strings.Contains(message, "URL_THROW ")
			if strings.Contains(message, "URL_WRITE ") {
				writes++
			}
		}
		if executed && event != nil && complete && (!continued || writes == 2) {
			return event, messages
		}
		if !executed && event != nil {
			return event, messages
		}
		if time.Now().After(deadline) {
			if executed {
				t.Fatalf("customer execution did not complete (disconnect=%t): %v", continued, messages)
			}
			return event, messages
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// SDK desired state is immediately visible, while admission/CORS uses the
// previous effective state until the shared deterministic one-minute boundary.
// SQLite restart must retain both the pending transition and URL identity.
func TestLambdaURLsDockerPropagationRestart(t *testing.T) {
	lambdaURLDocker(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			var closeDB func()
			path := t.TempDir() + "/url-propagation.sqlite"
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			r := newLambdaURLReplay(t, "urls_http", backends, nil)
			for _, row := range r.fixture.Observations {
				if row.Label == "set_cors" {
					break
				}
				r.command(t, row)
			}
			var endpoint string
			for _, value := range r.urls {
				endpoint = value
			}
			advanceClock(t, r.clock, time.Minute)
			cors := &lambdatypes.Cors{AllowOrigins: []string{"https://allowed.example"}, AllowMethods: []string{"GET"}}
			_, err := r.c.lambda.UpdateFunctionUrlConfig(t.Context(), &awslambda.UpdateFunctionUrlConfigInput{FunctionName: &r.fixture.Prefix, AuthType: lambdatypes.FunctionUrlAuthTypeAwsIam, Cors: cors})
			if err != nil {
				t.Fatal(err)
			}
			desired, err := r.c.lambda.GetFunctionUrlConfig(t.Context(), &awslambda.GetFunctionUrlConfigInput{FunctionName: &r.fixture.Prefix})
			if err != nil {
				t.Fatal(err)
			}
			if desired.AuthType != lambdatypes.FunctionUrlAuthTypeAwsIam || !reflect.DeepEqual(desired.Cors, cors) {
				t.Fatalf("desired configuration not immediately visible: %+v", desired)
			}
			origin := ""
			request := func(t *testing.T, want int) {
				req := r.request(t, endpoint, "/", "GET", [][2]string{{"X-Probe-Mode", "json"}, {"Origin", "https://allowed.example"}}, nil)
				client := r.httpClient()
				defer client.CloseIdleConnections()
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(res.Body)
				res.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if res.StatusCode != want {
					t.Fatalf("effective auth status=%d want %d: %s", res.StatusCode, want, data)
				}
				if want == 200 && res.Header.Get("Access-Control-Allow-Origin") != origin {
					t.Fatalf("effective CORS got %q want %q", res.Header.Get("Access-Control-Allow-Origin"), origin)
				}
			}
			request(t, 200)
			advanceClock(t, r.clock, 59*time.Second)
			if backend == "sqlite" {
				if err := r.c.cloud.Close(); err != nil {
					t.Fatal(err)
				}
				r.c.server.Close()
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
				r.connect(t, backends)
				restored, err := r.c.lambda.GetFunctionUrlConfig(t.Context(), &awslambda.GetFunctionUrlConfigInput{FunctionName: &r.fixture.Prefix})
				if err != nil {
					t.Fatal(err)
				}
				old, _ := url.Parse(endpoint)
				fresh, _ := url.Parse(aws.ToString(restored.FunctionUrl))
				if old.Path != fresh.Path {
					t.Fatal("restart changed URL identity")
				}
				endpoint = aws.ToString(restored.FunctionUrl)
				if restored.AuthType != desired.AuthType || !reflect.DeepEqual(restored.Cors, desired.Cors) {
					t.Fatal("restart lost desired URL configuration")
				}
			}
			request(t, 200)
			advanceClock(t, r.clock, time.Second)
			request(t, 403)
			// Updating only auth preserves CORS, including across the earlier restart.
			if _, err := r.c.lambda.UpdateFunctionUrlConfig(t.Context(), &awslambda.UpdateFunctionUrlConfigInput{FunctionName: &r.fixture.Prefix, AuthType: lambdatypes.FunctionUrlAuthTypeNone}); err != nil {
				t.Fatal(err)
			}
			request(t, 403)
			advanceClock(t, r.clock, time.Minute)
			origin = "https://allowed.example"
			request(t, 200)
		})
	}
}
