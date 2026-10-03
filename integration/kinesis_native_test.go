package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type kinesisNativeCall struct {
	Sequence                       int
	Label, Operation, Region, Code string
	Input, Output                  json.RawMessage
	HTTPStatus                     int `json:"httpStatus"`
}

type kinesisObservation struct {
	Label, Service, Operation string
	Input                     json.RawMessage
	RequestIDs                []string
	StartedAt, FinishedAt     time.Time
	Result                    struct {
		Code   string
		Output json.RawMessage
	}
}

type kinesisReplaySelection struct {
	Name, Source string
	Rows         []int
	ReopenAfter  []int
}

func TestKinesisNativeControls(t *testing.T) {
	var manifest struct{ Workflows []kinesisReplaySelection }
	kinesisReadFixture(t, "replay", &manifest)
	for _, workflow := range manifest.Workflows {
		t.Run(workflow.Name, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) { replayKinesisControls(t, backend, workflow) })
			}
		})
	}
}

func kinesisReadFixture(t *testing.T, name string, out any) {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/kinesis/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

func replayKinesisControls(t *testing.T, backend string, workflow kinesisReplaySelection) {
	t.Helper()
	runtime := newKinesisReplayRuntime(t)
	source := clock.NewManual(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC))
	cloud, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source, KinesisRuntime: runtime})
	var capture struct{ Calls []kinesisNativeCall }
	kinesisReadFixture(t, workflow.Source, &capture)
	rows := make(map[int]kinesisNativeCall, len(capture.Calls))
	for _, row := range capture.Calls {
		rows[row.Sequence] = row
	}
	bindings := map[string]string{}
	for _, number := range workflow.Rows {
		row, ok := rows[number]
		if !ok {
			t.Fatalf("missing native call %d", number)
		}
		if !t.Run(fmt.Sprintf("%03d_%s", number, row.Label), func(t *testing.T) {
			advanceClock(t, source, time.Second)
			wire := &awstest.WireClient{Client: cloud.server.Client()}
			client := kinesis.New(kinesis.Options{Region: row.Region, BaseEndpoint: aws.String(cloud.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: wire, RetryMaxAttempts: 1})
			input := json.RawMessage(aasReplace(string(row.Input), bindings))
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			_, err := awstest.CallSDK(ctx, client, row.Operation, input)
			if row.Code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				assertAPIError(t, err, row.Code)
			}
			if row.HTTPStatus != 0 && wire.Status != row.HTTPStatus {
				t.Fatalf("HTTP status %d want %d", wire.Status, row.HTTPStatus)
			}
			if row.Code == "Success" {
				want, got := ecsControlBody(t, row.Output), ecsControlBody(t, wire.Body)
				kinesisBindResponse(t, want, got, bindings)
				encoded, _ := json.Marshal(want)
				want = ecsControlBody(t, []byte(aasReplace(string(encoded), bindings)))
				if !reflect.DeepEqual(want, got) {
					t.Fatalf("native semantic response mismatch\n got %s\nwant %s", mustKinesisJSON(t, got), mustKinesisJSON(t, want))
				}
				// Native transition captures are selected only at stable reads. Real
				// Kafka readiness, not an elapsed delay alone, gates the next command.
				switch row.Operation {
				case "CreateStream", "IncreaseStreamRetentionPeriod", "DecreaseStreamRetentionPeriod", "EnableEnhancedMonitoring", "DisableEnhancedMonitoring", "UpdateStreamMode", "UpdateMaxRecordSize", "StartStreamEncryption", "StopStreamEncryption", "UpdateShardCount":
					fields := ecsControlBody(t, input)
					name, _ := fields["StreamName"].(string)
					if name == "" {
						arn, _ := fields["StreamARN"].(string)
						_, name, _ = strings.Cut(arn, ":stream/")
					}
					awaitKinesisActive(t, source, cloud.kinesis("test", "test", ""), name)
				}
			}
		}) {
			return
		}
		if slices.Contains(workflow.ReopenAfter, number) {
			cloud = reopen()
		}
	}
}

func mustKinesisJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// Bind opaque identities/cursors, not public metadata or topology. Timestamp
// values are environment-specific but their presence and numeric shape remain
// compared. Metric lists and policy JSON are unordered AWS sets/documents.
func kinesisBindResponse(t *testing.T, want, got map[string]any, bindings map[string]string) {
	t.Helper()
	for key, value := range want {
		actual, exists := got[key]
		if !exists {
			continue
		} // DeepEqual reports missing output fields.
		switch {
		case strings.HasSuffix(key, "Timestamp"):
			if _, ok := actual.(float64); !ok {
				t.Fatalf("invalid %s: %v", key, actual)
			}
			want[key] = actual
		case key == "NextToken" || key == "StartingSequenceNumber" || key == "EndingSequenceNumber" || key == "KeyId":
			native, nativeOK := value.(string)
			local, localOK := actual.(string)
			if !nativeOK || !localOK || local == "" {
				t.Fatalf("invalid %s identity: native=%v local=%v", key, value, actual)
			}
			if key == "NextToken" {
				bindings[native] = local
			} else {
				aasBind(t, bindings, native, local)
			}
		case key == "Policy":
			want[key] = ecsControlBody(t, []byte(value.(string)))
			got[key] = ecsControlBody(t, []byte(actual.(string)))
		case key == "CurrentShardLevelMetrics" || key == "DesiredShardLevelMetrics" || key == "ShardLevelMetrics":
			for _, list := range []any{value, actual} {
				if items, ok := list.([]any); ok {
					slices.SortFunc(items, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
				}
			}
		default:
			switch value := value.(type) {
			case map[string]any:
				if local, ok := actual.(map[string]any); ok {
					kinesisBindResponse(t, value, local, bindings)
				}
			case []any:
				if local, ok := actual.([]any); ok && len(local) == len(value) {
					for i, item := range value {
						if object, ok := item.(map[string]any); ok {
							if other, ok := local[i].(map[string]any); ok {
								kinesisBindResponse(t, object, other, bindings)
							}
						}
					}
				}
			}
		}
	}
}
