package stackd_test

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	schedulertypes "github.com/aws/aws-sdk-go-v2/service/scheduler/types"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

type schedulerPipesNativeCall struct {
	Label      string          `json:"label"`
	Service    string          `json:"service"`
	Operation  string          `json:"operation"`
	Parameters json.RawMessage `json:"parameters"`
	Code       string          `json:"code"`
	Output     json.RawMessage `json:"output"`
}

// This replays native admission, replacement, defaults, tags, conflicts and
// missing-resource errors. Runtime delivery/recovery is exercised separately by
// scheduler_pipes_executable_smoke.py against the actual executable and engines.
func TestSchedulerPipesNativeSDKLifecycle(t *testing.T) {
	for _, name := range []string{"lifecycle_success", "default_input"} {
		t.Run(name, func(t *testing.T) {
			replaySchedulerPipesNativeFixture(t, name)
		})
	}
}

func replaySchedulerPipesNativeFixture(t *testing.T, name string) {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/scheduler_pipes/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		StartedAt        time.Time                  `json:"started_at"`
		Identity         struct{ Account string }   `json:"identity"`
		Calls            []schedulerPipesNativeCall `json:"calls"`
		WorkflowComplete bool                       `json:"workflow_complete"`
		CleanupComplete  bool                       `json:"cleanup_complete"`
		CloudTrail       struct {
			Events []struct {
				Label string         `json:"call_label"`
				Event map[string]any `json:"event"`
			} `json:"events"`
		} `json:"cloudtrail"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if !fixture.WorkflowComplete || !fixture.CleanupComplete {
		t.Fatal("native lifecycle did not complete with owned resource cleanup")
	}
	nativeAudits := make(map[string]map[string]any)
	for _, row := range fixture.CloudTrail.Events {
		if row.Label != "" {
			nativeAudits[row.Label] = row.Event
		}
	}
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			backends := storage.NewMemory()
			if kind == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "scheduler-pipes.sqlite"))
			}
			source := clock.NewManual(fixture.StartedAt.Truncate(time.Second))
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			credential := credentials.NewStaticCredentialsProvider(fixture.Identity.Account, "test", "")
			scheduleClient := scheduler.New(scheduler.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL),
				Credentials: credential, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			pipeClient := pipes.New(pipes.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL),
				Credentials: credential, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL),
				Credentials: credential, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			for _, row := range fixture.Calls {
				if !schedulerPipesReplayCall(row) {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					var client any
					switch row.Service {
					case "iam":
						client = clients.iam(fixture.Identity.Account, "test", "")
					case "sqs":
						client = clients.sqs(fixture.Identity.Account, "test", "")
					case "scheduler":
						client = scheduleClient
					case "pipes":
						client = pipeClient
					}
					if _, err := cloud.RunDueJobs(t.Context(), 128); err != nil {
						t.Fatal(err)
					}
					native := nativeAudits[row.Label]
					parameters := row.Parameters
					if request, ok := native["requestParameters"].(map[string]any); ok && request["clientToken"] != nil {
						var input map[string]any
						if err := json.Unmarshal(parameters, &input); err != nil {
							t.Fatal(err)
						}
						input["ClientToken"] = request["clientToken"]
						parameters, err = json.Marshal(input)
						if err != nil {
							t.Fatal(err)
						}
					}
					out, err := awstest.CallSDK(t.Context(), client, strings.ReplaceAll(row.Operation, "_", "-"), parameters)
					got := "Success"
					if err != nil {
						var apiError smithy.APIError
						if !errors.As(err, &apiError) {
							t.Fatal(err)
						}
						got = apiError.ErrorCode()
					}
					if got != row.Code {
						t.Fatalf("native code %s, local %s: %v", row.Code, got, err)
					}
					if native != nil && (row.Service == "scheduler" || row.Service == "pipes") {
						want := maps.Clone(native)
						want["eventTime"] = source.Now().UTC().Format(time.RFC3339)
						if response, ok := want["responseElements"].(map[string]any); ok && out != nil {
							response = maps.Clone(response)
							for _, name := range []string{"CreationTime", "LastModifiedTime"} {
								if _, present := response[name]; !present {
									continue
								}
								stamp := reflect.ValueOf(out).Elem().FieldByName(name).Interface().(*time.Time)
								if stamp == nil {
									t.Fatalf("native audit timestamp %s lacks an SDK response value", name)
								}
								response[name] = float64(stamp.UnixNano()) / float64(time.Second)
							}
							want["responseElements"] = response
						}
						id := nativeAuditRequestID(t, out, err)
						event := auditLookupRecord(t, trails, id, native["eventName"].(string))
						assertNativeAuditEvent(t, event, want, "")
						actualVersion, present := event["apiVersion"]
						nativeVersion, nativePresent := want["apiVersion"]
						if present != nativePresent || !reflect.DeepEqual(actualVersion, nativeVersion) {
							t.Fatalf("native apiVersion presence/value differs: actual %#v, native %#v", event, want)
						}
					}
					if got == "Success" && schedulerPipesCompareSnapshot(row.Label) {
						var document map[string]json.RawMessage
						if err := json.Unmarshal(row.Output, &document); err != nil {
							t.Fatal(err)
						}
						for _, field := range []string{"ResponseMetadata", "CreationDate", "LastModificationDate", "CreationTime", "LastModifiedTime"} {
							delete(document, field)
						}
						expectedDocument, err := json.Marshal(document)
						if err != nil {
							t.Fatal(err)
						}
						want := reflect.New(reflect.TypeOf(out).Elem()).Interface()
						if err := awstest.DecodeSDK(expectedDocument, want); err != nil {
							t.Fatal(err)
						}
						for _, output := range []any{want, out} {
							if tags, ok := output.(*scheduler.ListTagsForResourceOutput); ok {
								slices.SortFunc(tags.Tags, func(a, b schedulertypes.Tag) int {
									return strings.Compare(aws.ToString(a.Key), aws.ToString(b.Key))
								})
							}
							value := reflect.ValueOf(output).Elem()
							for _, field := range []string{"ResultMetadata", "CreationDate", "LastModificationDate", "CreationTime", "LastModifiedTime"} {
								if member := value.FieldByName(field); member.IsValid() {
									member.SetZero()
								}
							}
						}
						if !reflect.DeepEqual(out, want) {
							actual, _ := json.Marshal(out)
							expected, _ := json.Marshal(want)
							t.Fatalf("native resource snapshot differs\nwant %s\ngot  %s", expected, actual)
						}
					}
				})
				if t.Failed() {
					return // Later lifecycle observations depend on this native step.
				}
			}
		})
	}
}

func schedulerPipesCompareSnapshot(label string) bool {
	switch label {
	case "get-group", "get-schedule", "get-updated-schedule", "group-tags", "pipe-tags", "get-defaults", "get-omitted-input":
		return true
	}
	return false
}

func schedulerPipesReplayCall(row schedulerPipesNativeCall) bool {
	if strings.HasPrefix(row.Label, "create-queue-") || strings.HasPrefix(row.Label, "create-role-") || strings.HasPrefix(row.Label, "role-policy-") {
		return true
	}
	switch row.Label {
	case "queue", "role", "role-policy", "group", "create-defaults", "get-defaults", "create-omitted-input", "get-omitted-input":
		return true
	case "create-group", "get-group", "group-tags", "tag-group", "untag-group", "duplicate-group",
		"create-schedule", "get-schedule", "duplicate-schedule", "invalid-cron", "invalid-zone",
		"window-missing-size", "date-order", "missing-group", "empty-input", "absent-input", "rate-plural", "at-past", "dst-gap", "at-bounds",
		"update-schedule", "get-updated-schedule", "list-owned-schedules", "get-missing-schedule",
		"create-pipe-stopped", "duplicate-pipe", "pipe-tags", "update-pipe", "pipe-missing",
		"start-pipe", "stop-pipe", "delete-pipe":
		return true
	}
	return false
}
