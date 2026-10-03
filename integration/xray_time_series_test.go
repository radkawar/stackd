package stackd_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type xraySeriesObservation struct {
	Case, Operation, Code string
	At                    json.RawMessage
	Input, Output         json.RawMessage
}

type xraySeriesCapture struct {
	Prefix, Region, Account string
	Observations            []xraySeriesObservation
}

func TestXRayTimeSeriesNativeSDK(t *testing.T) {
	var captured, settled xraySeriesCapture
	awsReadFixture(t, "xray/time_series_west.json", &captured)
	awsReadFixture(t, "xray/time_series_settled.json", &settled)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, phase := range []string{"first-indexed-batch", "settled"} {
			t.Run(backend+"/"+phase, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "series.sqlite")
				backends, closeDB := storage.NewMemory(), func() {}
				if backend == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, path)
				}
				var batches []xraySeriesObservation
				for _, row := range captured.Observations {
					if row.Operation == "put_trace_segments" {
						batches = append(batches, row)
					}
				}
				var first string
				awsDecodeJSON(t, batches[0].At, &first)
				epoch, err := time.Parse(time.RFC3339Nano, first)
				if err != nil {
					t.Fatal(err)
				}
				source := clock.NewManual(epoch.Add(-time.Second))
				_, clients, closeStack := startEventDeliveryCloud(t, backends, source)
				defer func() { closeStack(); closeDB() }()
				client := clients.xrayRegion(captured.Region, captured.Account, "test", "")
				group, err := client.CreateGroup(t.Context(), &xray.CreateGroupInput{GroupName: aws.String(captured.Prefix), FilterExpression: aws.String(`service("` + captured.Prefix + `-front")`)})
				if err != nil {
					t.Fatal(err)
				}
				for i, batch := range batches {
					// The early native read indexed only the first batch. Replay its
					// indexed data, not an invented fixed indexing delay.
					if phase != "settled" && i > 0 {
						break
					}
					var stamp string
					awsDecodeJSON(t, batch.At, &stamp)
					at, err := time.Parse(time.RFC3339Nano, stamp)
					if err != nil {
						t.Fatal(err)
					}
					advanceClock(t, source, at.Sub(source.Now()))
					var input xray.PutTraceSegmentsInput
					awsDecodeJSON(t, batch.Input, &input)
					out, err := client.PutTraceSegments(t.Context(), &input)
					if err != nil || len(out.UnprocessedTraceSegments) != 0 {
						t.Fatalf("ingest: %v, %+v", err, out)
					}
				}
				if backend == "sqlite" {
					closeStack()
					closeDB()
					backends, closeDB = openSQLiteBackends(t, path)
					_, clients, closeStack = startEventDeliveryCloud(t, backends, source)
				}
				rows := captured.Observations
				if phase == "settled" {
					rows = settled.Observations
				}
				for _, row := range rows {
					if row.Operation != "get_time_series_service_statistics" || row.Case == "old-group-membership" || row.Case == "await-owned-statistics" {
						continue
					}
					t.Run(row.Case, func(t *testing.T) {
						var input map[string]any
						awsDecodeJSON(t, row.Input, &input)
						if input["GroupARN"] != nil {
							input["GroupARN"] = aws.ToString(group.Group.GroupARN)
						}
						body, err := json.Marshal(input)
						if err != nil {
							t.Fatal(err)
						}
						wire := &awstest.WireClient{Client: clients.server.Client()}
						options := clients.xrayRegion(captured.Region, captured.Account, "test", "").Options()
						options.HTTPClient = wire
						options.APIOptions = append(options.APIOptions, awstest.JSONBody(body))
						_, err = xray.New(options).GetTimeSeriesServiceStatistics(t.Context(), &xray.GetTimeSeriesServiceStatisticsInput{StartTime: aws.Time(source.Now()), EndTime: aws.Time(source.Now())})
						if row.Code != "Success" {
							var modeled smithy.APIError
							if !errors.As(err, &modeled) || modeled.ErrorCode() != row.Code {
								t.Fatalf("want %s, got %v", row.Code, err)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						want, got := canonicalXRaySeries(t, row.Output), canonicalXRaySeries(t, wire.Body)
						if !reflect.DeepEqual(want, got) {
							t.Fatalf("native: %#v\nlocal: %#v", want, got)
						}
					})
				}
				// Account and region scopes must not inherit the indexed buckets.
				for _, scope := range [][2]string{{captured.Region, "999999999999"}, {"eu-west-1", captured.Account}} {
					other := clients.xrayRegion(scope[0], scope[1], "test", "")
					out, err := other.GetTimeSeriesServiceStatistics(t.Context(), &xray.GetTimeSeriesServiceStatisticsInput{StartTime: aws.Time(epoch.Add(-time.Hour)), EndTime: aws.Time(epoch.Add(time.Hour))})
					if err != nil || len(out.TimeSeriesServiceStatistics) != 0 {
						t.Fatalf("scope leaked: %+v, %v", out, err)
					}
				}
			})
		}
	}
}

func canonicalXRaySeries(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	awsDecodeJSON(t, raw, &out)
	delete(out, "ResponseMetadata")
	points, _ := out["TimeSeriesServiceStatistics"].([]any)
	for _, item := range points {
		point := item.(map[string]any)
		if text, ok := point["Timestamp"].(string); ok {
			stamp, err := time.Parse("2006-01-02 15:04:05Z07:00", text)
			if err != nil {
				t.Fatal(err)
			}
			point["Timestamp"] = float64(stamp.Unix())
		}
		if histogram, ok := point["ResponseTimeHistogram"].([]any); ok {
			slices.SortFunc(histogram, func(a, b any) int {
				av, bv := a.(map[string]any)["Value"].(float64), b.(map[string]any)["Value"].(float64)
				if av < bv {
					return -1
				}
				if av > bv {
					return 1
				}
				return 0
			})
		}
	}
	return out
}
