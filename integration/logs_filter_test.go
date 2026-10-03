package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

func TestLogsNativeFiltersSDK(t *testing.T) {
	var fixture struct {
		Corpus []struct {
			Index     int `json:"original_event_index"`
			Timestamp int64
			Message   string
		}
		Observations []struct {
			Label string
			Input json.RawMessage
		}
		Comparisons []struct {
			Label   string   `json:"oracle_label"`
			Queries []string `json:"filter_log_events_labels"`
			Code    string   `json:"filter_log_events_code"`
			Indices []int    `json:"filter_log_events_original_event_indices"`
		}
	}
	data, err := os.ReadFile("../testdata/aws/logs/filters.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	requests := map[string]json.RawMessage{}
	for _, row := range fixture.Observations {
		requests[row.Label] = row.Input
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "filters.sqlite"))
			}
			source := clock.NewManual(time.UnixMilli(fixture.Corpus[len(fixture.Corpus)-1].Timestamp).UTC())
			cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := cloud.Close(); err != nil {
					t.Error(err)
				}
			}()
			server := httptest.NewServer(cloud)
			defer server.Close()
			client := logsClient(cloudClients{server}, "test")
			for _, operation := range []struct{ Name, Label string }{{"CreateLogGroup", "create_owned_group"}, {"CreateLogStream", "create_owned_stream"}} {
				if _, err := awstest.CallSDK(t.Context(), client, operation.Name, requests[operation.Label]); err != nil {
					t.Fatal(err)
				}
			}
			var destination cloudwatchlogs.CreateLogStreamInput
			if err := json.Unmarshal(requests["create_owned_stream"], &destination); err != nil {
				t.Fatal(err)
			}
			input := &cloudwatchlogs.PutLogEventsInput{LogGroupName: destination.LogGroupName, LogStreamName: destination.LogStreamName}
			indices := map[int64]int{}
			messages := map[int64]string{}
			for _, event := range fixture.Corpus {
				input.LogEvents = append(input.LogEvents, logtypes.InputLogEvent{Timestamp: new(event.Timestamp), Message: new(event.Message)})
				indices[event.Timestamp], messages[event.Timestamp] = event.Index, event.Message
			}
			if _, err := client.PutLogEvents(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			for _, comparison := range fixture.Comparisons {
				t.Run(comparison.Label, func(t *testing.T) {
					var query cloudwatchlogs.FilterLogEventsInput
					if err := json.Unmarshal(requests[comparison.Queries[0]], &query); err != nil {
						t.Fatal(err)
					}
					// Force multiple pages, including scans containing only unmatched
					// events. The expected complete sequence remains native evidence.
					query.Limit = aws.Int32(2)
					var matched []int
					terminal := false
					for range 100 {
						out, err := client.FilterLogEvents(t.Context(), &query)
						if comparison.Code != "Success" {
							assertAPIError(t, err, comparison.Code)
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						for _, event := range out.Events {
							ts := aws.ToInt64(event.Timestamp)
							index, found := indices[ts]
							if !found || aws.ToString(event.Message) != messages[ts] || aws.ToString(event.LogStreamName) != *destination.LogStreamName {
								t.Fatalf("filter changed original event: %+v", event)
							}
							matched = append(matched, index)
						}
						if out.NextToken == nil {
							terminal = true
							break
						}
						query.NextToken = out.NextToken
					}
					if !terminal || !reflect.DeepEqual(matched, comparison.Indices) && !(len(matched) == 0 && len(comparison.Indices) == 0) {
						t.Fatalf("matches %v; native %v; terminal %v", matched, comparison.Indices, terminal)
					}
				})
			}
		})
	}
}
