package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"stackd/internal/awstest"
	"stackd/storage"
)

// These captures deliberately isolate requests in separate minutes. Replaying
// their service timestamps distinguishes absent error samples from explicit zero
// and keeps a handler 500 distinct from a runtime exception's HTTP 502.
type lambdaURLObservationFixture struct {
	lambdaURLFixture
	FunctionName    string `json:"function_name"`
	FunctionARN     string `json:"function_arn"`
	Bucket, Trail   string
	Actor           struct{ Account, Arn, UserID string }
	Cases           []lambdaURLObservationHTTP                      `json:"http_cases"`
	Records         []map[string]any                                `json:"cloudtrail_records"`
	MetricSnapshots []struct{ Series []lambdaURLObservationSeries } `json:"metric_snapshots"`
}

type lambdaURLObservationHTTP struct {
	Label, Token string
	StartedAt    time.Time `json:"started_at"`
	Request      struct {
		Method, URL string
		Headers     map[string]string
		Signed      bool
	}
	Configuration struct {
		AuthType string
	} `json:"effective_configuration"`
	Response struct {
		Status  int
		Headers [][2]string
		Body    string         `json:"body_base64"`
		JSON    map[string]any `json:"body_json"`
	}
}

type lambdaURLObservationSeries struct {
	Input  json.RawMessage
	Output struct{ Datapoints []metrictypes.Datapoint }
}

func TestLambdaURLsDockerCloudTrailAndCloudWatchNativeReplay(t *testing.T) {
	lambdaURLDocker(t)
	f := lambdaFixture[lambdaURLObservationFixture](t, "urls_observability_http")
	metricFixture := lambdaFixture[lambdaURLObservationFixture](t, "urls_observability_metrics")
	dimensions := lambdaFixture[struct{ Series []lambdaURLObservationSeries }](t, "urls_observability_dimensions")
	delivery := lambdaFixture[lambdaURLObservationFixture](t, "urls_observability_delivery")
	stream := lambdaFixture[lambdaURLObservationFixture](t, "urls_observability_stream")
	management := lambdaFixture[struct {
		Records []struct{ Record map[string]any }
	}](t, "urls_observability_management")
	if len(f.Cases) == 0 || len(metricFixture.MetricSnapshots) == 0 || len(dimensions.Series) == 0 {
		t.Fatal("native isolated HTTP/metric evidence is missing")
	}
	r := newLambdaURLReplay(t, "urls_observability_http", storage.NewMemory(), nil)
	r.fixture.Prefix = f.FunctionName
	r.normalize = strings.NewReplacer(f.Actor.Account, "000000000000")
	clients := cloudClients{r.c.server}
	objects := s3NativeClient(clients, "test", "test")
	trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: r.c.server.Client(), RetryMaxAttempts: 1})
	managementIDs := map[string]string{}
	var endpoint string
	// Retain the native exact-function data selector and ordinary trail/S3
	// policy. No synthetic projection or CloudTrail Lake reader substitutes for
	// the selected, gzip-encoded S3 objects consumed below.
	command := func(row lambdaURLRow) {
		var client any
		switch row.Service {
		case "s3":
			client = objects
		case "cloudtrail":
			client = trails
		default:
			if !strings.Contains(row.Operation, "function_url_config") {
				r.command(t, row)
				return
			}
			client = r.c.lambda
		}
		input := lambdaStreamingInput[map[string]any](t, row.Input, r.normalize)
		out, err := awstest.CallSDK(t.Context(), client, lambdaURLObservationOperation(row.Operation), lambdaQualifiedJSON(t, input))
		if err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
		if strings.Contains(row.Operation, "function_url_config") {
			managementIDs[row.Operation] = nativeAuditRequestID(t, out, nil)
		}
		if created, ok := out.(*awslambda.CreateFunctionUrlConfigOutput); ok {
			endpoint = aws.ToString(created.FunctionUrl)
		}
	}
	for _, row := range f.Observations {
		if row.Operation == "update_function_url_config" {
			break
		}
		if row.Service == "sts" {
			continue
		}
		command(row)
	}
	if endpoint == "" {
		t.Fatal("native setup did not create a function URL")
	}

	// Replay the captured IAMUser identity, with a local issued key and only the
	// URL action. Native evidence establishes that InvokeFunction is not needed.
	root := clients.iam("test", "test", "")
	userName := f.Actor.Arn[strings.LastIndex(f.Actor.Arn, "/")+1:]
	user, err := root.CreateUser(t.Context(), &iam.CreateUserInput{UserName: &userName})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: &userName, PolicyName: aws.String("url-invocation"), PolicyDocument: aws.String(string(lambdaQualifiedJSON(t, map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "lambda:InvokeFunctionUrl", "Resource": r.normalize.Replace(f.FunctionARN)}}})))}); err != nil {
		t.Fatal(err)
	}
	issued, err := root.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: &userName})
	if err != nil {
		t.Fatal(err)
	}
	key := aws.Credentials{AccessKeyID: aws.ToString(issued.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(issued.AccessKey.SecretAccessKey)}
	nativeKey := ""
	for _, h := range f.Cases {
		if h.Request.Signed {
			parts := strings.Split(strings.Split(h.Request.Headers["Authorization"], "Credential=")[1], "/")
			nativeKey = parts[0]
			break
		}
	}
	if nativeKey == "" {
		t.Fatal("capture lacks signed IAM control")
	}
	r.normalize = strings.NewReplacer(f.Actor.Account, "000000000000", f.Actor.UserID, aws.ToString(user.User.UserId), nativeKey, key.AccessKeyID)
	requestIDs := map[string]string{}
	currentAuth := f.Cases[0].Configuration.AuthType
	for _, h := range f.Cases {
		if !t.Run(h.Label, func(t *testing.T) {
			if h.Configuration.AuthType != currentAuth {
				command(f.lambdaURLFixture.row(t, "update-url-iam"))
				currentAuth = h.Configuration.AuthType
			}
			// Advancing to captured minute boundaries also applies the retained
			// one-minute URL configuration transition without a wall-clock sleep.
			advanceClock(t, r.clock, h.StartedAt.Sub(r.clock.Now()))
			requestIDs[h.Label] = lambdaURLObservationRequest(t, r, endpoint, h, key)
			trailNativeDrain(t, r.c.cloud)
		}) {
			t.FailNow()
		}
	}
	advanceClock(t, r.clock, time.Minute)
	trailNativeDrain(t, r.c.cloud)

	t.Run("isolated-minute-metrics-and-exact-dimensions", func(t *testing.T) {
		series := append([]lambdaURLObservationSeries{}, metricFixture.MetricSnapshots[len(metricFixture.MetricSnapshots)-1].Series...)
		series = append(series, dimensions.Series...)
		for _, captured := range series {
			input := lambdaStreamingInput[cloudwatch.GetMetricStatisticsInput](t, captured.Input, r.normalize)
			out, err := metricsClient(clients, "test").GetMetricStatistics(t.Context(), &input)
			if err != nil {
				t.Fatal(err)
			}
			lambdaURLObservationMetrics(t, input, out.Datapoints, captured.Output.Datapoints)
		}
	})

	// Record management calls through the same producer but read their native
	// management history: the captured trail intentionally selects only data.
	command(f.lambdaURLFixture.row(t, "delete-url"))
	t.Run("management-native-projections", func(t *testing.T) {
		for _, captured := range management.Records {
			want := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, captured.Record), r.normalize)
			name := want["eventName"].(string)
			var id string
			for operation, requestID := range managementIDs {
				if strings.EqualFold(strings.ReplaceAll(operation, "_", ""), name) {
					id = requestID
				}
			}
			if id == "" {
				t.Fatalf("management capture %s has no replayed call", name)
			}
			got := auditLookupRecord(t, trails, id, name)
			for _, record := range []map[string]any{got, want} {
				if response, ok := record["responseElements"].(map[string]any); ok {
					for _, field := range []string{"functionUrl", "creationTime", "lastModifiedTime"} {
						if value, present := response[field]; present {
							if value == "" {
								t.Fatalf("empty management %s", field)
							}
							response[field] = "<generated>"
						}
					}
				}
			}
			lambdaQualifiedAuditProjection(t, got, want)
		}
	})

	// Execute the retained true streaming artifact only after the seven-request
	// metric window has been checked; it must not pollute the isolated oracle.
	t.Run("response-stream-206", func(t *testing.T) {
		streamNormalize := strings.NewReplacer(stream.FunctionName, f.FunctionName, f.Actor.Account, "000000000000")
		for _, row := range stream.Observations {
			if row.Operation == "get_function_configuration" {
				continue
			}
			input := lambdaStreamingInput[map[string]any](t, row.Input, streamNormalize)
			out, err := awstest.CallSDK(t.Context(), r.c.lambda, lambdaURLObservationOperation(row.Operation), lambdaQualifiedJSON(t, input))
			if err != nil {
				t.Fatalf("%s: %v", row.Label, err)
			}
			if created, ok := out.(*awslambda.CreateFunctionUrlConfigOutput); ok {
				endpoint = aws.ToString(created.FunctionUrl)
			}
			r.ready(t)
		}
		advanceClock(t, r.clock, time.Minute)
		for _, h := range stream.Cases {
			requestIDs[h.Label] = lambdaURLObservationRequest(t, r, endpoint, h, key)
		}
	})
	advanceClock(t, r.clock, 5*time.Minute)
	trailNativeDrain(t, r.c.cloud)
	trailNativeStatus(t, trails, f.Trail, true, true)
	t.Run("selected-cloudtrail-s3-native-invoke-records", func(t *testing.T) {
		records := trailNativeRecords(t, trailNativeObjects(t, objects, f.Bucket, "owned/AWSLogs/"))
		byRequest := map[string]map[string]any{}
		for _, record := range records {
			if record["eventCategory"] != "Data" || record["eventSource"] != "lambda.amazonaws.com" {
				t.Fatalf("exact native data selector leaked another event: %v", record)
			}
			id, _ := record["requestID"].(string)
			if byRequest[id] != nil {
				t.Fatalf("duplicate delivered URL request %s", id)
			}
			byRequest[id] = record
		}
		// The isolated and later delivery captures complement one another. Join
		// by captured HTTP request ID, never infer audit omission from a poll
		// that also missed executing controls (notably preflight/denial).
		for _, capture := range []lambdaURLObservationFixture{f, delivery} {
			cases := append(slices.Clone(capture.Cases), stream.Cases...)
			for _, native := range capture.Records {
				var label string
				for _, h := range cases {
					if lambdaURLObservationHeader(h.Response.Headers, "x-amzn-requestid") == native["requestID"] {
						label = h.Label
					}
				}
				if label == "" {
					t.Fatalf("native delivered record has no HTTP correlation: %v", native)
				}
				id := requestIDs[label]
				got := byRequest[id]
				if got == nil {
					t.Fatalf("%s: HTTP request %s missing from actual S3 delivery", label, id)
				}
				normalize := strings.NewReplacer(capture.FunctionName, f.FunctionName, f.Actor.Account, "000000000000", f.Actor.UserID, aws.ToString(user.User.UserId), nativeKey, key.AccessKeyID)
				want := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, native), normalize)
				lambdaQualifiedAuditProjection(t, got, want)
				for _, field := range []string{"userIdentity", "userAgent", "awsRegion", "recipientAccountId"} {
					if !reflect.DeepEqual(got[field], want[field]) {
						t.Fatalf("%s %s got %v native %v", label, field, got[field], want[field])
					}
				}
				shared, hasShared := got["sharedEventID"]
				_, nativeShared := want["sharedEventID"]
				if hasShared != nativeShared || (hasShared && (shared == "" || shared == got["eventID"])) {
					t.Fatalf("%s lost distinct native shared event identity: %v", label, got)
				}
				if got["eventID"] == nil || got["eventID"] == "" {
					t.Fatalf("%s missing event identity", label)
				}
			}
		}
	})
}

func lambdaURLObservationOperation(operation string) string {
	parts := strings.Split(operation, "_")
	for i, part := range parts {
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, "")
}

func lambdaURLObservationHeader(headers [][2]string, key string) string {
	for _, pair := range headers {
		if strings.EqualFold(pair[0], key) {
			return pair[1]
		}
	}
	return ""
}

func lambdaURLObservationRequest(t *testing.T, r *lambdaURLReplay, endpoint string, h lambdaURLObservationHTTP, key aws.Credentials) string {
	t.Helper()
	u, err := url.Parse(h.Request.URL)
	if err != nil {
		t.Fatal(err)
	}
	var headers [][2]string
	for name, value := range h.Request.Headers {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-Amz-Date") {
			continue
		}
		headers = append(headers, [2]string{name, value})
	}
	// Python's captured http.client supplies identity encoding automatically.
	headers = append(headers, [2]string{"Accept-Encoding", "identity"})
	request := r.request(t, endpoint, u.RequestURI(), h.Request.Method, headers, nil)
	if h.Request.Signed {
		lambdaURLSign(t, request, nil, key)
	}
	client := r.httpClient()
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != h.Response.Status {
		t.Fatalf("HTTP %d native %d: %q", response.StatusCode, h.Response.Status, body)
	}
	lambdaURLHeaders(t, response.Header, h.Response.Headers)
	id := response.Header.Get("x-amzn-requestid")
	if id == "" {
		t.Fatal("HTTP response omitted its request ID")
	}
	if lambdaURLObservationHeader(h.Response.Headers, "x-owned-runtime-request-id") != "" {
		if response.Header.Get("x-owned-runtime-request-id") != id {
			t.Fatal("HTTP and runtime response request IDs differ")
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		want := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, h.Response.JSON), r.normalize)
		if got["runtimeRequestId"] != id {
			t.Fatalf("body runtime request ID differs from HTTP: %v", got)
		}
		if got["event"].(map[string]any)["requestContext"].(map[string]any)["requestId"] != id {
			t.Fatal("customer event lost HTTP request identity")
		}
		lambdaURLEvent(t, got["event"].(map[string]any), want["event"].(map[string]any))
		delete(got, "event")
		delete(want, "event")
		delete(got, "runtimeRequestId")
		delete(want, "runtimeRequestId")
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("customer response got %v native %v", got, want)
		}
	} else {
		want, err := base64.StdEncoding.DecodeString(h.Response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if h.Response.Status == http.StatusForbidden {
			lambdaURLForbidden(t, body, want)
		} else {
			lambdaURLBody(t, body, want)
		}
	}
	// Runtime output supplies the join even for a thrown handler with no body.
	// Unlike the general URL fixture, this artifact logs OWNED_URL_EVENT and
	// has no URL_COMPLETE record, so use the existing Logs SDK client directly.
	executed := h.Request.Method != http.MethodOptions && !(h.Configuration.AuthType == "AWS_IAM" && !h.Request.Signed)
	if executed {
		deadline := time.Now().Add(10 * time.Second)
		for {
			out, err := logsClient(cloudClients{r.c.server}, "test").FilterLogEvents(t.Context(), &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String("/aws/lambda/" + r.fixture.Prefix), FilterPattern: aws.String(`"` + h.Token + `"`)})
			if err != nil {
				t.Fatal(err)
			}
			for _, log := range out.Events {
				message := aws.ToString(log.Message)
				index := strings.Index(message, "OWNED_URL_EVENT ")
				if index < 0 {
					continue
				}
				var info struct {
					Token, RuntimeRequestID string
					Event                   struct{ RequestContext struct{ RequestID string } }
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(message[index+len("OWNED_URL_EVENT "):])), &info); err != nil {
					t.Fatal(err)
				}
				if info.Token != h.Token {
					continue
				}
				if info.RuntimeRequestID != id || info.Event.RequestContext.RequestID != id {
					t.Fatalf("runtime log and HTTP request IDs differ: %s", message)
				}
				return id
			}
			if time.Now().After(deadline) {
				t.Fatalf("HTTP request %s has no corresponding real runtime log", id)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	return id
}

func lambdaURLObservationMetrics(t *testing.T, input cloudwatch.GetMetricStatisticsInput, got, want []metrictypes.Datapoint) {
	t.Helper()
	for _, points := range [][]metrictypes.Datapoint{got, want} {
		for _, point := range points {
			if point.Timestamp == nil {
				t.Fatalf("%s has an untimed datapoint", aws.ToString(input.MetricName))
			}
		}
	}
	slices.SortFunc(got, func(a, b metrictypes.Datapoint) int { return a.Timestamp.Compare(*b.Timestamp) })
	want = slices.Clone(want)
	slices.SortFunc(want, func(a, b metrictypes.Datapoint) int { return a.Timestamp.Compare(*b.Timestamp) })
	if len(got) != len(want) {
		t.Fatalf("%s %v datapoints got %+v native %+v; absent is not zero", aws.ToString(input.MetricName), input.Dimensions, got, want)
	}
	for i, actual := range got {
		expected := want[i]
		if actual.Timestamp == nil || expected.Timestamp == nil || !actual.Timestamp.Equal(*expected.Timestamp) || !reflect.DeepEqual(actual.SampleCount, expected.SampleCount) || actual.Unit != expected.Unit {
			t.Fatalf("%s %v minute/sample/unit got %+v native %+v", aws.ToString(input.MetricName), input.Dimensions, actual, expected)
		}
		if expected.Unit != metrictypes.StandardUnitMilliseconds {
			if !reflect.DeepEqual(actual.Sum, expected.Sum) {
				t.Fatalf("%s %v sum got %+v native %+v", aws.ToString(input.MetricName), input.Dimensions, actual, expected)
			}
			continue
		}
		for _, value := range []*float64{actual.Sum, actual.Minimum, actual.Maximum, actual.Average} {
			if value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 {
				t.Fatalf("invalid latency statistic: %+v", actual)
			}
		}
	}
}
