package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	metrictypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type logsMetricObservation struct {
	Label, Service, Operation string
	Input                     json.RawMessage
	Started                   int64 `json:"request_started_ms"`
	Result                    struct {
		Code   string
		Output json.RawMessage
	}
}

type logsMetricFixture struct {
	Account, Group, Namespace string
	Observations              []logsMetricObservation
}

func loadLogsMetricFixture(t *testing.T, name string) logsMetricFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/logs/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture logsMetricFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestLogsNativeMetricFiltersSDK(t *testing.T) {
	for _, name := range []string{"metric_filters", "metric_filter_extractors"} {
		fixture := loadLogsMetricFixture(t, name)
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(name+"/"+backend, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					var closeDB func()
					backends, closeDB = openSQLiteBackends(t, filepath.Join(t.TempDir(), "metrics.sqlite"))
					t.Cleanup(closeDB)
				}
				source := clock.NewManual(time.UnixMilli(fixture.Observations[0].Started).UTC())
				cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source, AccountID: fixture.Account})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := cloud.Close(); err != nil {
						t.Error(err)
					}
				})
				c := cloudClients{httptest.NewServer(cloud)}
				t.Cleanup(c.server.Close)
				logs, metrics := logsClient(c, "test"), metricsClient(c, "test")
				created := map[string]int64{}
				var pageToken *string
				for _, row := range fixture.Observations {
					if row.Service == "sts" || row.Result.Code == "CLIError" {
						continue
					}
					// Polling absence and PartialData describe bounded native visibility,
					// not non-delivery. Replay only positive CloudWatch observations.
					if row.Service == "cloudwatch" {
						if row.Result.Code != "Success" {
							continue
						}
						switch row.Operation {
						case "get-metric-data":
							var expected cloudwatch.GetMetricDataOutput
							if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
								t.Fatal(err)
							}
							hasPoints := false
							for _, result := range expected.MetricDataResults {
								hasPoints = hasPoints || len(result.Values) != 0
							}
							if !hasPoints {
								continue
							}
							out, err := awstest.CallSDK(t.Context(), metrics, "GetMetricData", row.Input)
							if err != nil {
								t.Fatalf("%s: %v", row.Label, err)
							}
							actual := out.(*cloudwatch.GetMetricDataOutput)
							for _, want := range expected.MetricDataResults {
								if len(want.Values) == 0 {
									continue
								}
								var got *metrictypes.MetricDataResult
								for i := range actual.MetricDataResults {
									if aws.ToString(actual.MetricDataResults[i].Id) == aws.ToString(want.Id) {
										got = &actual.MetricDataResults[i]
										break
									}
								}
								if got == nil || len(got.Timestamps) != len(got.Values) {
									t.Fatalf("%s/%s: got %+v, native %+v", row.Label, aws.ToString(want.Id), got, want)
								}
								// Historical samples may appear hours after publication in AWS.
								// Require every positively observed bucket, not an absence that
								// the finite capture cannot establish as permanent.
								for i, timestamp := range want.Timestamps {
									found := false
									for j, actualTime := range got.Timestamps {
										if actualTime.Equal(timestamp) {
											found = true
											if got.Values[j] != want.Values[i] {
												t.Fatalf("%s/%s at %v: got %g, native %g", row.Label, aws.ToString(want.Id), timestamp, got.Values[j], want.Values[i])
											}
											break
										}
									}
									if !found {
										t.Fatalf("%s/%s: missing native timestamp %v", row.Label, aws.ToString(want.Id), timestamp)
									}
								}
							}
						case "get-metric-statistics":
							var expected cloudwatch.GetMetricStatisticsOutput
							if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
								t.Fatal(err)
							}
							if len(expected.Datapoints) == 0 {
								continue
							}
							out, err := awstest.CallSDK(t.Context(), metrics, "GetMetricStatistics", row.Input)
							if err != nil {
								t.Fatalf("%s: %v", row.Label, err)
							}
							for _, want := range expected.Datapoints {
								found := false
								for _, got := range out.(*cloudwatch.GetMetricStatisticsOutput).Datapoints {
									if got.Timestamp.Equal(*want.Timestamp) && got.Unit == want.Unit {
										found = true
										if !reflect.DeepEqual(got.Sum, want.Sum) || !reflect.DeepEqual(got.SampleCount, want.SampleCount) || !reflect.DeepEqual(got.Minimum, want.Minimum) || !reflect.DeepEqual(got.Maximum, want.Maximum) || !reflect.DeepEqual(got.Average, want.Average) {
											t.Fatalf("%s: got %+v, native %+v", row.Label, got, want)
										}
									}
								}
								if !found {
									t.Fatalf("%s: missing native datapoint %+v", row.Label, want)
								}
							}
						}
						continue
					}
					// Event read polling is not the metric-filter oracle; ingestion is
					// checked by rejection indices and actual CloudWatch observations.
					if row.Operation == "get-log-events" || row.Operation == "describe-log-groups" {
						continue
					}
					if at := time.UnixMilli(row.Started); at.After(source.Now()) {
						advanceClock(t, source, at.Sub(source.Now()))
					}
					operation := ""
					for _, word := range strings.Split(row.Operation, "-") {
						operation += strings.ToUpper(word[:1]) + word[1:]
					}
					out, err := awstest.CallSDK(t.Context(), logs, operation, row.Input, func(value any) {
						if row.Label == "describe-page-two" {
							value.(*cloudwatchlogs.DescribeMetricFiltersInput).NextToken = pageToken
						}
					})
					if row.Result.Code != "Success" {
						assertAPIError(t, err, row.Result.Code)
						continue
					}
					if err != nil {
						t.Fatalf("%s: %v", row.Label, err)
					}
					switch out := out.(type) {
					case *cloudwatchlogs.TestMetricFilterOutput:
						var expected cloudwatchlogs.TestMetricFilterOutput
						if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
							t.Fatal(err)
						}
						if len(out.Matches) != len(expected.Matches) {
							t.Fatalf("%s: matches %+v, native %+v", row.Label, out.Matches, expected.Matches)
						}
						for i, got := range out.Matches {
							want := expected.Matches[i]
							if got.EventNumber != want.EventNumber || aws.ToString(got.EventMessage) != aws.ToString(want.EventMessage) || !(len(got.ExtractedValues) == 0 && len(want.ExtractedValues) == 0) && !reflect.DeepEqual(got.ExtractedValues, want.ExtractedValues) {
								t.Fatalf("%s: match %+v, native %+v", row.Label, got, want)
							}
						}
					case *cloudwatchlogs.DescribeMetricFiltersOutput:
						var expected cloudwatchlogs.DescribeMetricFiltersOutput
						if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
							t.Fatal(err)
						}
						if len(out.MetricFilters) != len(expected.MetricFilters) {
							t.Fatalf("%s: filters %+v, native %+v", row.Label, out.MetricFilters, expected.MetricFilters)
						}
						for i, got := range out.MetricFilters {
							want := expected.MetricFilters[i]
							key := aws.ToString(got.FilterName)
							if aws.ToString(got.FilterName) != aws.ToString(want.FilterName) || aws.ToString(got.FilterPattern) != aws.ToString(want.FilterPattern) || aws.ToString(got.LogGroupName) != aws.ToString(want.LogGroupName) || !reflect.DeepEqual(got.MetricTransformations, want.MetricTransformations) || got.ApplyOnTransformedLogs != want.ApplyOnTransformedLogs || aws.ToString(got.FieldSelectionCriteria) != aws.ToString(want.FieldSelectionCriteria) || !reflect.DeepEqual(got.EmitSystemFieldDimensions, want.EmitSystemFieldDimensions) {
								t.Fatalf("%s: config %+v, native %+v", row.Label, got, want)
							}
							if first, ok := created[key]; ok && aws.ToInt64(got.CreationTime) != first {
								t.Fatalf("%s: replacement changed creation time for %s", row.Label, key)
							}
							created[key] = aws.ToInt64(got.CreationTime)
						}
						if row.Label == "describe-page-one" {
							if out.NextToken == nil {
								t.Fatal("first limited filter page lost continuation")
							}
							pageToken = out.NextToken
						}
						if row.Label == "publication-filters-roundtrip" {
							var names, want []string
							for _, filter := range expected.MetricFilters {
								want = append(want, aws.ToString(filter.FilterName))
							}
							query := &cloudwatchlogs.DescribeMetricFiltersInput{LogGroupName: aws.String(fixture.Group), Limit: aws.Int32(2)}
							terminal := false
							for range 100 {
								page, err := logs.DescribeMetricFilters(t.Context(), query)
								if err != nil {
									t.Fatal(err)
								}
								for _, filter := range page.MetricFilters {
									names = append(names, aws.ToString(filter.FilterName))
								}
								if page.NextToken == nil {
									terminal = true
									break
								}
								query.NextToken = page.NextToken
							}
							if !terminal || !reflect.DeepEqual(names, want) {
								t.Fatalf("filter pagination got %v, native %v, terminal %v", names, want, terminal)
							}
						}
					case *cloudwatchlogs.PutLogEventsOutput:
						var expected struct {
							RejectedLogEventsInfo *logtypes.RejectedLogEventsInfo
						}
						if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(out.RejectedLogEventsInfo, expected.RejectedLogEventsInfo) {
							t.Fatalf("%s: rejection %+v, native %+v", row.Label, out.RejectedLogEventsInfo, expected.RejectedLogEventsInfo)
						}
					}
				}
			})
		}
	}
}
