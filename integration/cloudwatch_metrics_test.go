package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http/protocol/awsquery"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

func metricsClient(c cloudClients, key string) *cloudwatch.Client {
	return cloudwatch.New(cloudwatch.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

type nativeMetricObservation struct {
	Label, Operation     string
	Input                json.RawMessage
	Started              int64 `json:"request_started_ms"`
	VisibilityIncomplete bool  `json:"visibility_incomplete"`
	Result               struct {
		Code       string
		Output     json.RawMessage
		HTTPStatus int `json:"http_status"`
	}
}

type nativeMetricFixture struct {
	Scope struct {
		Anchor int64 `json:"anchor_seconds"`
	}
	Identity struct {
		Account string `json:"expected_caller_account"`
	} `json:"identity_relationships"`
	Observations []nativeMetricObservation
}

func loadMetricFixture(t *testing.T, name string) nativeMetricFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/cloudwatch/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture nativeMetricFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f nativeMetricFixture) row(t *testing.T, label string) nativeMetricObservation {
	t.Helper()
	for _, row := range f.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("missing native metric observation %q", label)
	return nativeMetricObservation{}
}

func metricFixtureCloud(t *testing.T, backend string, fixture nativeMetricFixture) (cloudClients, *clock.Manual) {
	t.Helper()
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "metrics.sqlite"))
	}
	source := clock.NewManual(time.Unix(fixture.Scope.Anchor, 0).UTC())
	cloud, err := stackd.New(stackd.Config{AccountID: fixture.Identity.Account, Storage: backends, Clock: source})
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
	return cloudClients{server}, source
}

func replayMetric(t *testing.T, client *cloudwatch.Client, row nativeMetricObservation, mutations ...func(any)) any {
	t.Helper()
	operation := ""
	for _, word := range strings.Split(row.Operation, "-") {
		operation += strings.ToUpper(word[:1]) + word[1:]
	}
	out, err := awstest.CallSDK(t.Context(), client, operation, row.Input, mutations...)
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		var response interface{ HTTPStatusCode() int }
		if row.Result.HTTPStatus != 0 && (!errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus) {
			t.Fatalf("%s: HTTP status differs from native %d: %v", row.Label, row.Result.HTTPStatus, err)
		}
		return nil
	}
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	return out
}

// Native JSON represents non-finite response numbers as strings. Preserve NaN
// rather than dropping zero-count datapoints or comparing their JSON spelling.
type nativeMetricNumber float64

func (n *nativeMetricNumber) UnmarshalJSON(data []byte) error {
	if string(data) == `"NaN"` {
		*n = nativeMetricNumber(math.NaN())
		return nil
	}
	var value float64
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*n = nativeMetricNumber(value)
	return nil
}

func equalMetricNumber(got float64, want nativeMetricNumber) bool {
	value := float64(want)
	if math.IsNaN(value) {
		return math.IsNaN(got)
	}
	if math.IsInf(value, 0) {
		return got == value
	}
	return got == value || math.Abs(got-value) <= 1e-10*math.Abs(value)
}

func assertMetricStatistics(t *testing.T, got *cloudwatch.GetMetricStatisticsOutput, output json.RawMessage) {
	t.Helper()
	var want struct {
		Label      string
		Datapoints []struct {
			Timestamp                                   time.Time
			Unit                                        string
			SampleCount, Sum, Minimum, Maximum, Average *nativeMetricNumber
			ExtendedStatistics                          map[string]nativeMetricNumber
		}
	}
	if err := json.Unmarshal(output, &want); err != nil {
		t.Fatal(err)
	}
	if aws.ToString(got.Label) != want.Label || len(got.Datapoints) != len(want.Datapoints) {
		t.Fatalf("statistics label/count: %s, %d datapoints; native %s, %d", aws.ToString(got.Label), len(got.Datapoints), want.Label, len(want.Datapoints))
	}
	// AWS does not promise GetMetricStatistics datapoint order; units can share a timestamp.
	for _, expected := range want.Datapoints {
		var actual *metrictypes.Datapoint
		for i := range got.Datapoints {
			point := &got.Datapoints[i]
			if point.Timestamp != nil && point.Timestamp.Equal(expected.Timestamp) && string(point.Unit) == expected.Unit {
				if actual != nil {
					t.Fatalf("duplicate timestamp/unit: %v %s", expected.Timestamp, expected.Unit)
				}
				actual = point
			}
		}
		if actual == nil {
			t.Fatalf("missing native datapoint %v %s", expected.Timestamp, expected.Unit)
		}
		for _, field := range []struct {
			name string
			got  *float64
			want *nativeMetricNumber
		}{
			{"SampleCount", actual.SampleCount, expected.SampleCount}, {"Sum", actual.Sum, expected.Sum},
			{"Minimum", actual.Minimum, expected.Minimum}, {"Maximum", actual.Maximum, expected.Maximum}, {"Average", actual.Average, expected.Average},
		} {
			if (field.got == nil) != (field.want == nil) {
				t.Fatalf("%s %v %s: present %v, native present %v", want.Label, expected.Timestamp, field.name, field.got != nil, field.want != nil)
			}
			if field.got != nil && !equalMetricNumber(*field.got, *field.want) {
				t.Fatalf("%s %v %s: got %g, native %g", want.Label, expected.Timestamp, field.name, *field.got, *field.want)
			}
		}
		if len(actual.ExtendedStatistics) != len(expected.ExtendedStatistics) {
			t.Fatalf("%s extended eligibility: %v; native %v", want.Label, actual.ExtendedStatistics, expected.ExtendedStatistics)
		}
		for stat, value := range expected.ExtendedStatistics {
			got, ok := actual.ExtendedStatistics[stat]
			if !ok || !equalMetricNumber(got, value) {
				t.Fatalf("%s %v %s: %g; native %g", want.Label, expected.Timestamp, stat, got, value)
			}
		}
	}
}

func assertMetricData(t *testing.T, got *cloudwatch.GetMetricDataOutput, output json.RawMessage) {
	t.Helper()
	var want struct {
		MetricDataResults []struct {
			Id, Label  *string
			StatusCode metrictypes.StatusCode
			Timestamps []time.Time
			Values     []nativeMetricNumber
			Messages   []metrictypes.MessageData
		}
		NextToken *string
		Messages  []metrictypes.MessageData
	}
	if err := awstest.DecodeSDK(output, &want); err != nil {
		t.Fatal(err)
	}
	if len(got.MetricDataResults) != len(want.MetricDataResults) || (got.NextToken == nil) != (want.NextToken == nil) {
		t.Fatalf("result count/pagination: %+v; native %s", got, output)
	}
	messageCodes := func(messages []metrictypes.MessageData) []string {
		codes := make([]string, len(messages))
		for i, message := range messages {
			codes[i] = aws.ToString(message.Code)
		}
		return codes
	}
	if !reflect.DeepEqual(messageCodes(got.Messages), messageCodes(want.Messages)) {
		t.Fatalf("response messages: %v; native %v", got.Messages, want.Messages)
	}
	// AWS identifies results by query ID and label; neither query-result order
	// nor the order of SEARCH identities with the same label is a contract.
	remaining := map[[2]string][]metrictypes.MetricDataResult{}
	for _, result := range got.MetricDataResults {
		key := [2]string{aws.ToString(result.Id), aws.ToString(result.Label)}
		remaining[key] = append(remaining[key], result)
	}
	for _, expected := range want.MetricDataResults {
		key := [2]string{aws.ToString(expected.Id), aws.ToString(expected.Label)}
		candidates := remaining[key]
		matched := -1
		for i, actual := range candidates {
			if (actual.Id == nil) != (expected.Id == nil) || (actual.Label == nil) != (expected.Label == nil) || actual.StatusCode != expected.StatusCode || len(actual.Timestamps) != len(expected.Timestamps) || len(actual.Values) != len(expected.Values) || !reflect.DeepEqual(messageCodes(actual.Messages), messageCodes(expected.Messages)) {
				continue
			}
			equal := true
			for j, timestamp := range expected.Timestamps {
				if !actual.Timestamps[j].Equal(timestamp) {
					equal = false
					break
				}
			}
			for j, value := range expected.Values {
				if !equalMetricNumber(actual.Values[j], value) {
					equal = false
					break
				}
			}
			if equal {
				matched = i
				break
			}
		}
		if matched < 0 {
			t.Fatalf("result %s/%s: %+v; native %+v", key[0], key[1], candidates, expected)
		}
		remaining[key] = append(candidates[:matched], candidates[matched+1:]...)
	}
}

func TestCloudWatchNativePublicationSDK(t *testing.T) {
	fixture := loadMetricFixture(t, "metrics")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, source := metricFixtureCloud(t, backend, fixture)
			client := metricsClient(c, "test")
			// Entity-associated publication is unsupported, not a passing native
			// comparison. Historical reads and visibility polls are separate evidence.
			for _, row := range fixture.Observations {
				if row.Operation != "put-metric-data" || strings.HasPrefix(row.Label, "entity-") {
					continue
				}
				if at := time.UnixMilli(row.Started); at.After(source.Now()) {
					advanceClock(t, source, at.Sub(source.Now()))
				}
				t.Run(row.Label, func(t *testing.T) { replayMetric(t, client, row) })
			}
			for _, row := range fixture.Observations {
				selected := strings.HasPrefix(row.Label, "statistics-") && row.Label != "statistics-Entity" ||
					strings.HasPrefix(row.Label, "percentiles-") || strings.HasPrefix(row.Label, "unit-") ||
					strings.HasPrefix(row.Label, "dimension-") || strings.HasPrefix(row.Label, "resolution-") ||
					row.Label == "admitted-validation-terminal" || row.Label == "admitted-validation-percentiles" ||
					row.Label == "extended-trimmed-statistics" || row.Label == "colon-namespace-terminal" ||
					row.Label == "reserved-terminal" || strings.HasPrefix(row.Label, "window-or-validation-") && row.Result.Code != "CLIError"
				if !selected {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					out := replayMetric(t, client, row)
					if out != nil {
						assertMetricStatistics(t, out.(*cloudwatch.GetMetricStatisticsOutput), row.Result.Output)
					}
				})
			}
			for _, label := range []string{"list-terminal-subset-name", "list-subset-value", "list-wrong-dimension", "list-wrong-account", "list-invalid-recent", "list-invalid-token"} {
				t.Run(label, func(t *testing.T) {
					row := fixture.row(t, label)
					out := replayMetric(t, client, row)
					if out == nil {
						return
					}
					var expected cloudwatch.ListMetricsOutput
					if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
						t.Fatal(err)
					}
					identities := func(metrics []metrictypes.Metric) []string {
						keys := make([]string, len(metrics))
						for i, metric := range metrics {
							dimensions := make([]string, len(metric.Dimensions))
							for j, dimension := range metric.Dimensions {
								dimensions[j] = aws.ToString(dimension.Name) + "=" + aws.ToString(dimension.Value)
							}
							sort.Strings(dimensions)
							keys[i] = fmt.Sprint(aws.ToString(metric.Namespace), "/", aws.ToString(metric.MetricName), dimensions)
						}
						sort.Strings(keys)
						return keys
					}
					actual := out.(*cloudwatch.ListMetricsOutput)
					if !reflect.DeepEqual(identities(actual.Metrics), identities(expected.Metrics)) {
						t.Fatalf("metric identities: %v; native %v", actual.Metrics, expected.Metrics)
					}
				})
			}
		})
	}
}

func TestCloudWatchNativeMetricDataSDK(t *testing.T) {
	fixture := loadMetricFixture(t, "metrics")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, _ := metricFixtureCloud(t, backend, fixture)
			client := metricsClient(c, "test")
			for _, label := range []string{"publish-baselines", "publish-repeat-and-reversed-dimensions"} {
				replayMetric(t, client, fixture.row(t, label))
			}
			for _, label := range []string{"data-default-descending", "data-ascending", "data-resolution", "data-units", "data-math", "data-invalid-token", "data-duplicate-id", "data-expression-and-metric", "data-invalid-expression", "data-invalid-id", "data-invalid-stat", "data-valid-account", "data-wrong-account"} {
				t.Run(label, func(t *testing.T) {
					row := fixture.row(t, label)
					out := replayMetric(t, client, row)
					if out != nil {
						assertMetricData(t, out.(*cloudwatch.GetMetricDataOutput), row.Result.Output)
					}
				})
			}
			for _, direction := range []string{"TimestampAscending", "TimestampDescending"} {
				t.Run("pagination-"+direction, func(t *testing.T) {
					var token *string
					for page := range 3 {
						row := fixture.row(t, fmt.Sprintf("data-page-%s-%d", direction, page))
						out, err := awstest.CallSDK(t.Context(), client, "GetMetricData", row.Input, func(value any) { value.(*cloudwatch.GetMetricDataInput).NextToken = token })
						if err != nil {
							t.Fatal(err)
						}
						actual := out.(*cloudwatch.GetMetricDataOutput)
						assertMetricData(t, actual, row.Result.Output)
						token = actual.NextToken
					}
					if token != nil {
						t.Fatal("pagination did not terminate")
					}
				})
			}
			// A different authenticated account cannot read the populated series.
			row := fixture.row(t, "data-ascending")
			out := replayMetric(t, metricsClient(c, "444444444444"), row).(*cloudwatch.GetMetricDataOutput)
			for _, result := range out.MetricDataResults {
				if len(result.Values) != 0 || len(result.Timestamps) != 0 {
					t.Fatalf("cross-account metric leak: %+v", result)
				}
			}
		})
	}
}

func TestCloudWatchCompressedRPCQueryAtomicitySDK(t *testing.T) {
	fixture := loadMetricFixture(t, "metrics")
	data, err := os.ReadFile("../testdata/aws/cloudwatch/protocol_errors.json")
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		RPC struct {
			Code string `json:"error_code"`
		} `json:"sdk_result"`
		Query struct {
			Code string `json:"sdk_code"`
		} `json:"query_capture"`
	}
	if err := json.Unmarshal(data, &native); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, _ := metricFixtureCloud(t, backend, fixture)
			// Observe the real HTTP boundary; the SDK still serializes, compresses,
			// signs and decodes both protocols without an in-process transport fake.
			var compressed, queryRequests atomic.Int64
			observer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Smithy-Protocol") == "rpc-v2-cbor" && r.Header.Get("Content-Encoding") == "gzip" {
					compressed.Add(1)
				}
				if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
					queryRequests.Add(1)
				}
				c.server.Config.Handler.ServeHTTP(w, r)
			}))
			defer observer.Close()
			opts := metricsClient(cloudClients{observer}, "test").Options()
			rpc := cloudwatch.New(opts)
			query := cloudwatch.New(opts, func(o *cloudwatch.Options) { o.Protocol = awsquery.New(&smithy.ServiceSchema{Version: "2010-08-01"}) })
			// Exceed the SDK's default compression threshold with copies of one
			// fixture datum under a separate identity. Original series and native
			// expected values remain unchanged; no compression override is used.
			var padding []metrictypes.MetricDatum
			_, err := awstest.CallSDK(t.Context(), rpc, "PutMetricData", fixture.row(t, "publish-baselines").Input, func(value any) {
				input := value.(*cloudwatch.PutMetricDataInput)
				datum := input.MetricData[0]
				datum.MetricName = aws.String(strings.Repeat(aws.ToString(datum.MetricName), 32))
				for range 64 {
					padding = append(padding, datum)
				}
				input.MetricData = append(input.MetricData, padding...)
			})
			if err != nil {
				t.Fatal(err)
			}
			replayMetric(t, query, fixture.row(t, "publish-repeat-and-reversed-dimensions"))
			for _, client := range []*cloudwatch.Client{rpc, query} {
				row := fixture.row(t, "statistics-Scalar")
				assertMetricStatistics(t, replayMetric(t, client, row).(*cloudwatch.GetMetricStatisticsOutput), row.Result.Output)
			}
			var invalid, valid cloudwatch.PutMetricDataInput
			if err := json.Unmarshal(fixture.row(t, "admission-value-and-values").Input, &invalid); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(fixture.row(t, "publish-baselines").Input, &valid); err != nil {
				t.Fatal(err)
			}
			// Prepend a valid datum to the native conflicting publication. Rejecting
			// the entire batch must leave the already-observed Scalar sum unchanged.
			invalid.MetricData = append(valid.MetricData[:1:1], invalid.MetricData...)
			invalid.MetricData = append(invalid.MetricData, padding...)
			for _, protocol := range []struct {
				name, code string
				client     *cloudwatch.Client
			}{
				{"rpc", native.RPC.Code, rpc}, {"query", native.Query.Code, query},
			} {
				t.Run(protocol.name, func(t *testing.T) {
					_, err := protocol.client.PutMetricData(t.Context(), &invalid)
					assertAPIError(t, err, protocol.code)
					var modeled *metrictypes.InvalidParameterCombinationException
					if !errors.As(err, &modeled) {
						t.Fatalf("not a modeled invalid combination: %T %v", err, err)
					}
					var response interface{ HTTPStatusCode() int }
					if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusBadRequest {
						t.Fatalf("invalid batch HTTP status: %v", err)
					}
					row := fixture.row(t, "statistics-Scalar")
					assertMetricStatistics(t, replayMetric(t, rpc, row).(*cloudwatch.GetMetricStatisticsOutput), row.Result.Output)
				})
			}
			if compressed.Load() < 2 || queryRequests.Load() < 3 {
				t.Fatalf("compression/interoperability paths not exercised: compressed %d, Query %d", compressed.Load(), queryRequests.Load())
			}
		})
	}
}
