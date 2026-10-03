package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
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
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type gatewayMetricWindow struct {
	Start, End time.Time
}

type gatewayMetricHTTP struct {
	Label, API, Path, Method string
	StartedAt                time.Time         `json:"started_at"`
	RequestHeaders           map[string]string `json:"request_headers"`
	Result                   struct {
		Status int
		Body   map[string]any
	}
}

type gatewayMetricFixture struct {
	gatewayTimelineFixture
	Owned   map[string]any
	HTTP    []gatewayMetricHTTP
	Cohorts []struct {
		Name         string
		Window       gatewayMetricWindow
		MetricWindow gatewayMetricWindow `json:"metric_window"`
	}
	MetricQueries []struct {
		ObservationLabel  string `json:"observation_label"`
		Purpose, Protocol string
	} `json:"metric_queries"`
	Sockets []gatewayMetricSocket `json:"websocket_observations"`
}

type gatewayMetricQuery struct {
	row                 gatewaySDKObservation
	protocol            string
	excludedByteMinutes map[int64]bool
	variableByteMinutes map[int64]bool
}

type gatewayMetricReplay struct {
	t        *testing.T
	fixture  gatewayMetricFixture
	clients  cloudClients
	owner    credentials.StaticCredentialsProvider
	bindings map[string]string
	sockets  map[string]*gatewayWSConn
}

func TestAPIGatewayNativeServiceMetrics(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 for real API Gateway metric runtimes")
	}
	for _, name := range []string{"rest_metrics", "v2_metrics"} {
		var fixture gatewayMetricFixture
		awsReadFixture(t, "apigateway/"+name+".json", &fixture)
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(name+"/"+backend, func(t *testing.T) {
				replayGatewayMetrics(t, fixture, backend)
			})
		}
	}
}

func replayGatewayMetrics(t *testing.T, fixture gatewayMetricFixture, backend string) {
	t.Helper()
	if len(fixture.Observations) == 0 || fixture.HandlerSource == "" || len(fixture.Cohorts) == 0 {
		t.Fatal("metric fixture lacks controls, captured handler or cohort windows")
	}
	queries := gatewayMetricQueries(t, fixture)
	source := clock.NewManual(fixture.Observations[0].StartedAt)
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	r := &gatewayMetricReplay{t: t, fixture: fixture, clients: clients,
		owner:    gatewayNativeUser(t, clients, fixture.Account, fixture.Region, fixture.Identity.Arn),
		bindings: map[string]string{}, sockets: map[string]*gatewayWSConn{}}
	defer func() {
		for _, socket := range r.sockets {
			_ = socket.Close()
		}
	}()

	var windows []gatewayMetricWindow
	var end time.Time
	for _, cohort := range fixture.Cohorts {
		window := cohort.Window
		if window.Start.IsZero() {
			window = cohort.MetricWindow
		}
		if !window.End.After(window.Start) {
			t.Fatalf("%s has no bounded native metric window", cohort.Name)
		}
		windows = append(windows, window)
		if window.End.After(end) {
			end = window.End
		}
	}
	inWindow := func(at time.Time) bool {
		for _, window := range windows {
			if !at.Before(window.Start) && at.Before(window.End) {
				return true
			}
		}
		return false
	}
	type step struct {
		at    time.Time
		kind  string
		index int
	}
	var steps []step
	var cleanup []gatewaySDKObservation
	settings := map[string]gatewaySDKObservation{}
	for index, row := range fixture.Observations {
		if strings.HasPrefix(row.Label, "cleanup-") || strings.HasPrefix(row.Label, "absence-") {
			if row.Service == "apigateway" || row.Service == "apigatewayv2" {
				cleanup = append(cleanup, row)
			}
			continue
		}
		// Publication polling and evidence collection are not execution traffic.
		// Failed Lambda creation is IAM propagation, not a semantic request.
		if row.Service == "cloudwatch" || row.Service == "logs" && row.Operation != "CreateLogGroup" || row.Operation == "CreateFunction" && row.Result.Code != "Success" || strings.Contains(row.Label, "ready-") {
			continue
		}
		if row.Service == "apigatewaymanagementapi" && !inWindow(row.StartedAt) {
			continue
		}
		steps = append(steps, step{row.StartedAt, "sdk", index})
	}
	for index, row := range fixture.HTTP {
		// Include readiness only when it actually contributes to a queried minute.
		if inWindow(row.StartedAt) {
			steps = append(steps, step{row.StartedAt, "http", index})
		}
	}
	for index, row := range fixture.Sockets {
		if inWindow(row.StartedAt) {
			steps = append(steps, step{row.StartedAt, "socket", index})
		}
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].at.Before(steps[j].at) })
	for _, step := range steps {
		if step.at.After(source.Now()) {
			source.Advance(step.at.Sub(source.Now()))
		}
		switch step.kind {
		case "sdk":
			row := fixture.Observations[step.index]
			r.call(row)
			if row.Operation == "GetStage" {
				encoded, err := json.Marshal(row.Input)
				if err != nil {
					t.Fatal(err)
				}
				settings[row.Service+string(encoded)] = row
			}
		case "http":
			r.http(fixture.HTTP[step.index])
		case "socket":
			r.socket(fixture.Sockets[step.index])
		}
	}
	if len(r.sockets) != 0 {
		t.Fatal("native metric replay left a live socket at the retention boundary")
	}
	if len(fixture.Sockets) == 0 {
		// Earlier minutes may already publish through the joined scheduler.
		// Reopen with completed requests from the current minute still pending,
		// before advancing service time across that minute's publication boundary.
		pending := -1
		for index, query := range queries {
			dimensions, _ := query.row.Input["Dimensions"].([]any)
			if query.row.Input["MetricName"] != "Count" || len(dimensions) != 1 {
				continue
			}
			start, err := time.Parse(time.RFC3339Nano, query.row.Input["StartTime"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if start.Equal(source.Now().Truncate(time.Minute)) {
				pending = index
				break
			}
		}
		if pending < 0 {
			t.Fatal("fixture lacks an API Count query for the pending request minute")
		}
		if got := r.statistics(queries[pending].row, r.owner); len(got.Datapoints) != 0 {
			t.Fatalf("current request minute published before its rollover: %v", got.Datapoints)
		}
		r.clients = reopen()
		for _, row := range settings {
			r.call(row)
		}
	}
	if end.After(source.Now()) {
		source.Advance(end.Sub(source.Now()))
	}
	r.drain()
	if len(fixture.Sockets) != 0 {
		r.awaitDisconnect(queries)
		// The callback witness must precede shutdown. This one V2 reopen
		// retains its enabled route settings and published series without
		// restarting any held connection; REST covers pending publication.
		r.clients = reopen()
		for _, row := range settings {
			r.call(row)
		}
	}

	baseline := make([][]cwtypes.Datapoint, len(queries))
	outsider := credentials.NewStaticCredentialsProvider("999999999999", "test", "")
	for index, query := range queries {
		got := r.statistics(query.row, r.owner)
		gatewayMetricCompare(t, query, got.Datapoints)
		baseline[index] = got.Datapoints
		if isolated := r.statistics(query.row, outsider); len(isolated.Datapoints) != 0 {
			t.Fatalf("%s leaked owner metrics to another account: %v", query.row.Label, isolated.Datapoints)
		}
	}
	for _, row := range cleanup {
		r.call(row)
	}
	for index, query := range queries {
		got := r.statistics(query.row, r.owner)
		gatewayMetricSort(got.Datapoints)
		gatewayMetricSort(baseline[index])
		if !reflect.DeepEqual(got.Datapoints, baseline[index]) {
			t.Fatalf("%s changed retained metric statistics after API deletion: got=%v before=%v", query.row.Label, got.Datapoints, baseline[index])
		}
	}
	if len(fixture.Sockets) != 0 {
		t.Log("WebSocket statistics compare the complete captured query window: native one-way messages straddled publication minute buckets; HTTP/REST compare individual minute buckets")
		t.Log("DataProcessed: native normal proxy-payload byte statistics are exact; only the IAM-rejection minute is excluded because pre-integration byte accounting is unresolved, and raised-error byte values use invariants because traceback paths vary")
	}
}

func gatewayMetricQueries(t *testing.T, fixture gatewayMetricFixture) []gatewayMetricQuery {
	t.Helper()
	observations := map[string]gatewaySDKObservation{}
	for _, row := range fixture.Observations {
		observations[row.Label] = row
	}
	excludedBytes, variableBytes := map[int64]bool{}, map[int64]bool{}
	for _, row := range fixture.HTTP {
		if row.API != "plain_http" {
			continue
		}
		minute := row.StartedAt.Truncate(time.Minute).Unix()
		if row.Result.Status == http.StatusForbidden && row.Result.Body["message"] == "Forbidden" {
			excludedBytes[minute] = true
		}
		if row.Result.Status >= 500 && row.Result.Body["invocation_id"] == nil {
			variableBytes[minute] = true
		}
	}
	latest := map[string]gatewayMetricQuery{}
	for _, link := range fixture.MetricQueries {
		if link.Purpose != "" && link.Purpose != "final-snapshot" {
			continue
		}
		row, ok := observations[link.ObservationLabel]
		if !ok || row.Service != "cloudwatch" || row.Operation != "GetMetricStatistics" || row.Result.Code != "Success" {
			t.Fatalf("invalid final metric query link %s", link.ObservationLabel)
		}
		encoded, err := json.Marshal(row.Input)
		if err != nil {
			t.Fatal(err)
		}
		key := string(encoded)
		if old, ok := latest[key]; !ok || row.StartedAt.After(old.row.StartedAt) {
			latest[key] = gatewayMetricQuery{row: row, protocol: link.Protocol,
				excludedByteMinutes: excludedBytes, variableByteMinutes: variableBytes}
		}
	}
	queries := make([]gatewayMetricQuery, 0, len(latest))
	for _, query := range latest {
		queries = append(queries, query)
	}
	sort.Slice(queries, func(i, j int) bool { return queries[i].row.Label < queries[j].row.Label })
	if len(queries) == 0 {
		t.Fatal("fixture has no linked final metric observations")
	}
	return queries
}

func (r *gatewayMetricReplay) call(row gatewaySDKObservation) {
	t := r.t
	t.Helper()
	if row.Actor.Arn != "" && row.Actor.Arn != r.fixture.Identity.Arn {
		t.Fatalf("%s has an unestablished actor %s", row.Label, row.Actor.Arn)
	}
	input := gatewayClone(t, row.Input)
	gatewaySubstitute(input, r.bindings)
	if row.Operation == "CreateFunction" {
		input["Code"] = map[string]any{"ZipFile": lambdaZIP(t, map[string]string{"index.py": r.fixture.HandlerSource})}
	}
	if blob, ok := row.Input["Data"].(map[string]any); ok {
		data, err := base64.StdEncoding.DecodeString(blob["base64"].(string))
		if err != nil {
			t.Fatal(err)
		}
		input["Data"] = data
	}
	endpoint := r.clients.server.URL
	if row.Service == "apigatewaymanagementapi" {
		nativeEndpoint := row.Endpoint
		if nativeEndpoint == "" {
			// The V2 metric capture stores its callback endpoint through the
			// held socket's URL rather than on each management observation.
			for _, socket := range r.fixture.Sockets {
				if socket.Operation == "connect" && socket.Result.Status == http.StatusSwitchingProtocols {
					parsed, err := url.Parse(socket.Request.URL)
					if err != nil {
						t.Fatal(err)
					}
					parsed.RawQuery = ""
					nativeEndpoint = parsed.String()
					break
				}
			}
		}
		endpoint = r.localURL(nativeEndpoint, false)
	}
	wire := &awstest.WireClient{Client: r.clients.server.Client()}
	client := gatewaySDKClient(t, row.Service, aws.Config{Region: r.fixture.Region, BaseEndpoint: aws.String(endpoint), Credentials: r.owner, HTTPClient: wire, RetryMaxAttempts: 1})
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
	if row.Operation == "GetStage" {
		want, got := gatewayMetricSettings(row.Result.Output), gatewayMetricSettings(actual)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s retained metric settings=%v native=%v", row.Label, got, want)
		}
	}
	gatewayBind(row.Result.Output, actual, r.bindings)
	if row.Operation == "CreateFunction" {
		function := actual["FunctionName"].(string)
		if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client)).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &function}, 30*time.Second, fastLambdaActiveWaiter); err != nil {
			t.Fatalf("%s: %v", row.Label, err)
		}
	}
}

func gatewayMetricSettings(value map[string]any) map[string]any {
	out := map[string]any{}
	var visit func(map[string]any, string)
	visit = func(object map[string]any, path string) {
		for key, child := range object {
			name := strings.ToLower(key)
			if name == "metricsenabled" || name == "detailedmetricsenabled" {
				out[path+"/"+name] = child
			} else if nested, ok := child.(map[string]any); ok {
				visit(nested, path+"/"+name)
			}
		}
	}
	visit(value, "")
	return out
}

func (r *gatewayMetricReplay) http(row gatewayMetricHTTP) {
	t := r.t
	t.Helper()
	api, _ := r.fixture.Owned[row.API+"_api"].(string)
	if api == "" {
		t.Fatalf("%s has no owned execution API %s", row.Label, row.API)
	}
	endpoint := "https://" + api + ".execute-api." + r.fixture.Region + ".amazonaws.com" + row.Path
	request, err := http.NewRequestWithContext(t.Context(), row.Method, r.localURL(endpoint, false), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range row.RequestHeaders {
		request.Header.Set(name, gatewayReplace(value, r.bindings))
	}
	if len(row.RequestHeaders) == 0 {
		// V2's inherited capture helper supplies these headers, also witnessed
		// in the captured Lambda events; its HTTP rows omit the header copy.
		request.Header.Set("User-Agent", "stackd-native-gateway-probe")
		request.Header.Set("X-Probe", row.Label)
	}
	request.Header.Set("Accept-Encoding", "identity")
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
	r.body(row.Label, row.Result.Body, body)
}

func (r *gatewayMetricReplay) body(label string, native map[string]any, body []byte) {
	t := r.t
	t.Helper()
	var actual map[string]any
	awsDecodeJSON(t, body, &actual)
	// Generated IDs are bound, not compared to AWS identities. All handler
	// outcomes and error classifications remain exact native observations.
	for _, key := range []string{"invocation", "invocation_id", "api_request_id", "requestId", "connection_id", "connectionId"} {
		before, beforeOK := native[key].(string)
		after, afterOK := actual[key].(string)
		if beforeOK {
			if !afterOK || after == "" {
				t.Fatalf("%s lacks generated %s: %s", label, key, body)
			}
			if bound, exists := r.bindings[before]; exists && bound != after {
				t.Fatalf("%s changed bound %s: %q != %q", label, key, after, bound)
			}
			r.bindings[before] = after
		}
	}
	want := gatewayClone(t, native)
	gatewaySubstitute(want, r.bindings)
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("%s body=%v native=%v", label, actual, want)
	}
}

func (r *gatewayMetricReplay) localURL(native string, socket bool) string {
	r.t.Helper()
	parsed, err := url.Parse(native)
	if err != nil {
		r.t.Fatal(err)
	}
	api, _, ok := strings.Cut(parsed.Host, ".execute-api.")
	local, bound := r.bindings[api]
	if !ok || !bound || local == "" {
		r.t.Fatalf("unbound native execution endpoint %q", native)
	}
	origin, err := url.Parse(r.clients.server.URL)
	if err != nil {
		r.t.Fatal(err)
	}
	parsed.Scheme, parsed.Host = origin.Scheme, origin.Host
	parsed.Path = "/_stackd/execute-api/" + local + parsed.Path
	parsed.RawPath = ""
	if socket {
		parsed.Scheme = "ws"
	}
	return parsed.String()
}

func (r *gatewayMetricReplay) statistics(row gatewaySDKObservation, owner aws.CredentialsProvider) *cloudwatch.GetMetricStatisticsOutput {
	r.t.Helper()
	input := gatewayClone(r.t, row.Input)
	gatewaySubstitute(input, r.bindings)
	encoded, err := json.Marshal(input)
	if err != nil {
		r.t.Fatal(err)
	}
	var query cloudwatch.GetMetricStatisticsInput
	awsDecodeJSON(r.t, encoded, &query)
	client := cloudwatch.New(cloudwatch.Options{Region: r.fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: owner, HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
	out, err := client.GetMetricStatistics(r.t.Context(), &query)
	if err != nil {
		r.t.Fatalf("%s: %v", row.Label, err)
	}
	return out
}

func gatewayMetricCompare(t *testing.T, query gatewayMetricQuery, actual []cwtypes.Datapoint) {
	t.Helper()
	encoded, err := json.Marshal(query.row.Result.Output)
	if err != nil {
		t.Fatal(err)
	}
	var native cloudwatch.GetMetricStatisticsOutput
	awsDecodeJSON(t, encoded, &native)
	metric := query.row.Input["MetricName"].(string)
	got, want := actual, native.Datapoints
	if metric == "DataProcessed" {
		filter := func(points []cwtypes.Datapoint) []cwtypes.Datapoint {
			out := make([]cwtypes.Datapoint, 0, len(points))
			for _, point := range points {
				if !query.excludedByteMinutes[aws.ToTime(point.Timestamp).Unix()] {
					out = append(out, point)
				}
			}
			return out
		}
		got, want = filter(got), filter(want)
	}
	if query.protocol == "WEBSOCKET" {
		// The native one-way execution witnesses occupy one minute, but its
		// published samples occupy two. Compare the measured population across
		// the full query window rather than inventing a local AWS dispatch lag.
		got = gatewayMetricAggregate(t, query.row.Label, got)
		want = gatewayMetricAggregate(t, query.row.Label, want)
	}
	gatewayMetricSort(got)
	gatewayMetricSort(want)
	if len(got) != len(want) {
		t.Errorf("%s datapoints=%d native=%d: got=%v native=%v", query.row.Label, len(got), len(want), got, want)
		return
	}
	for index, expected := range want {
		point := got[index]
		if point.Timestamp == nil || expected.Timestamp == nil || !point.Timestamp.Equal(*expected.Timestamp) || point.Unit != expected.Unit {
			t.Errorf("%s bucket/unit=%v/%s native=%v/%s", query.row.Label, point.Timestamp, point.Unit, expected.Timestamp, expected.Unit)
		}
		for _, field := range []struct {
			name      string
			got, want *float64
		}{
			{"SampleCount", point.SampleCount, expected.SampleCount}, {"Sum", point.Sum, expected.Sum},
			{"Minimum", point.Minimum, expected.Minimum}, {"Maximum", point.Maximum, expected.Maximum}, {"Average", point.Average, expected.Average},
		} {
			if field.got == nil || field.want == nil {
				t.Errorf("%s omitted %s: got=%v native=%v", query.row.Label, field.name, field.got, field.want)
				continue
			}
			if math.IsNaN(*field.got) || math.IsInf(*field.got, 0) || *field.got < 0 {
				t.Errorf("%s invalid %s=%v", query.row.Label, field.name, *field.got)
			}
			variableBytes := metric == "DataProcessed" && query.variableByteMinutes[aws.ToTime(expected.Timestamp).Unix()]
			if field.name != "SampleCount" && (strings.Contains(metric, "Latency") || variableBytes) {
				continue
			}
			if !gatewayMetricNear(*field.got, *field.want) {
				t.Errorf("%s %s=%v native=%v", query.row.Label, field.name, *field.got, *field.want)
			}
		}
		count, sum, average := aws.ToFloat64(point.SampleCount), aws.ToFloat64(point.Sum), aws.ToFloat64(point.Average)
		if count <= 0 || !gatewayMetricNear(sum, count*average) || aws.ToFloat64(point.Minimum) > average || average > aws.ToFloat64(point.Maximum) {
			t.Errorf("%s inconsistent statistic set: %v", query.row.Label, point)
		}
		if metric == "DataProcessed" && sum <= 0 {
			t.Errorf("%s lost a nonempty Lambda proxy/error payload: sum=%v bytes", query.row.Label, sum)
		}
		if metric == "IntegrationLatency" && query.protocol == "" && count >= 4 && aws.ToFloat64(point.Maximum) < 40 {
			// Each captured REST sample cohort executes a real 40ms handler sleep.
			// A manual-clock delta of zero is not an execution duration.
			t.Errorf("%s lost the real delayed Lambda duration: maximum=%vms", query.row.Label, aws.ToFloat64(point.Maximum))
		}
	}
}

func gatewayMetricNear(a, b float64) bool {
	return math.Abs(a-b) <= 1e-9*math.Max(1, math.Max(math.Abs(a), math.Abs(b)))
}

func gatewayMetricSort(points []cwtypes.Datapoint) {
	sort.Slice(points, func(i, j int) bool { return aws.ToTime(points[i].Timestamp).Before(aws.ToTime(points[j].Timestamp)) })
}

func gatewayMetricAggregate(t *testing.T, label string, points []cwtypes.Datapoint) []cwtypes.Datapoint {
	t.Helper()
	if len(points) == 0 {
		return nil
	}
	count, sum, minimum, maximum := 0.0, 0.0, math.Inf(1), 0.0
	unit := points[0].Unit
	for _, point := range points {
		if point.Unit != unit || point.SampleCount == nil || point.Sum == nil || point.Minimum == nil || point.Maximum == nil || point.Average == nil {
			t.Fatalf("%s cannot aggregate incomplete or mixed-unit statistics: %v", label, point)
		}
		for _, value := range []float64{*point.SampleCount, *point.Sum, *point.Minimum, *point.Maximum, *point.Average} {
			if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
				t.Fatalf("%s invalid statistic value %v", label, value)
			}
		}
		if *point.SampleCount <= 0 || !gatewayMetricNear(*point.Sum, *point.SampleCount**point.Average) || *point.Minimum > *point.Average || *point.Average > *point.Maximum {
			t.Fatalf("%s inconsistent metric bucket: %v", label, point)
		}
		count += *point.SampleCount
		sum += *point.Sum
		minimum = math.Min(minimum, *point.Minimum)
		maximum = math.Max(maximum, *point.Maximum)
	}
	return []cwtypes.Datapoint{{Timestamp: aws.Time(time.Unix(0, 0).UTC()), Unit: unit,
		SampleCount: aws.Float64(count), Sum: aws.Float64(sum), Minimum: aws.Float64(minimum), Maximum: aws.Float64(maximum), Average: aws.Float64(sum / count)}}
}

func (r *gatewayMetricReplay) drain() {
	r.t.Helper()
	for range 100 {
		jobs, err := r.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(r.t.Context(), 1000)
		if err != nil {
			r.t.Fatal(err)
		}
		if !jobs.More {
			return
		}
	}
	r.t.Fatal("due metric jobs did not settle")
}

func (r *gatewayMetricReplay) awaitDisconnect(queries []gatewayMetricQuery) {
	r.t.Helper()
	for _, query := range queries {
		if query.protocol != "WEBSOCKET" || query.row.Input["MetricName"] != "MessageCount" {
			continue
		}
		dimensions, _ := query.row.Input["Dimensions"].([]any)
		disconnect := false
		for _, raw := range dimensions {
			dimension, _ := raw.(map[string]any)
			disconnect = disconnect || dimension["Name"] == "Route" && dimension["Value"] == "$disconnect"
		}
		if !disconnect {
			continue
		}
		encoded, err := json.Marshal(query.row.Result.Output)
		if err != nil {
			r.t.Fatal(err)
		}
		var native cloudwatch.GetMetricStatisticsOutput
		awsDecodeJSON(r.t, encoded, &native)
		want := 0.0
		for _, point := range native.Datapoints {
			want += aws.ToFloat64(point.SampleCount)
		}
		// A peer-close echo precedes the asynchronous disconnect callback.
		// Its real CloudWatch population is the completion barrier, not a
		// guessed sleep or an internal publisher/transport mock.
		deadline := time.Now().Add(10 * time.Second)
		poll := time.NewTicker(10 * time.Millisecond)
		defer poll.Stop()
		for {
			r.drain()
			got := r.statistics(query.row, r.owner)
			count := 0.0
			for _, point := range got.Datapoints {
				count += aws.ToFloat64(point.SampleCount)
			}
			if count >= want {
				return
			}
			if time.Now().After(deadline) {
				r.t.Fatalf("disconnect metric callback did not complete: samples=%v native=%v", count, want)
			}
			select {
			case <-poll.C:
			case <-r.t.Context().Done():
				r.t.Fatal(r.t.Context().Err())
			}
		}
	}
	r.t.Fatal("WebSocket fixture lacks a disconnect metric completion witness")
}
