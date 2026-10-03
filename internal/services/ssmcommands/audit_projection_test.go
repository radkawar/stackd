package ssmcommands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"stackd/clock"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
)

// Replay API DTOs against independently captured CloudTrail documents. The
// recorder is exercised with both real journal backends; native execution output
// is input evidence, not a mock service response or an inferred audit document.
func TestNativeCommandAuditProjection(t *testing.T) {
	var fixture struct {
		Account, Region string
		History         struct {
			Events []struct {
				Label string `json:"call_label"`
				Event map[string]any
			}
		}
	}
	readFixture := func(name string, target any) {
		t.Helper()
		data, err := os.ReadFile("../../../testdata/aws/ssm/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatal(err)
		}
	}
	readFixture("managed_execution_audit.json", &fixture)
	type nativeCall struct {
		Label, Operation, Code string
		Input, Output          json.RawMessage
		Error                  struct{ Error struct{ Message string } }
	}
	calls := map[string]nativeCall{}
	for _, file := range []string{"managed_execution_current.json", "managed_execution_control_edges.json", "managed_execution_document_expiry.json"} {
		var source struct{ Calls []nativeCall }
		readFixture(file, &source)
		for _, call := range source.Calls {
			calls[file+":"+call.Label] = call
		}
	}
	expected := map[string]map[string]any{}
	for _, row := range fixture.History.Events {
		expected[row.Label] = row.Event
	}
	// Each row covers a distinct projection boundary. Repeated polling captures
	// are deliberately excluded. The four bounded-unobserved malformed fleet
	// calls provide no absence evidence and are not asserted here.
	labels := []string{
		"managed_execution_current.json:command-success-output",
		"managed_execution_current.json:send-missing-tag",
		"managed_execution_current.json:send-explicit-target-id",
		"managed_execution_current.json:send-custom-$DEFAULT",
		"managed_execution_document_expiry.json:expiry-send-hardcoded-omitted",
		"managed_execution_current.json:send-missing-document",
		"managed_execution_current.json:send-missing-version",
		"managed_execution_current.json:send-missing-instance",
		"managed_execution_current.json:send-unknown-parameter",
		"managed_execution_current.json:send-timeout-too-small",
		"managed_execution_current.json:send-concurrency-zero",
		"managed_execution_current.json:send-errors-negative",
		"managed_execution_current.json:role-before-deny-0",
		"managed_execution_current.json:command-cancel",
		"managed_execution_control_edges.json:cancel-missing-command",
		"managed_execution_control_edges.json:cancel-malformed-command",
		"managed_execution_current.json:success-commands",
		"managed_execution_current.json:success-plugins",
		"managed_execution_current.json:success-invocation-4",
		"managed_execution_current.json:invocation-missing-command",
		"managed_execution_current.json:invocation-wrong-plugin",
		"managed_execution_control_edges.json:invocation-invalid-id",
		"managed_execution_current.json:managed-node-online-5",
		"managed_execution_control_edges.json:fleet-missing-id",
		"managed_execution_control_edges.json:fleet-invalid-next-token",
		"managed_execution_control_edges.json:fleet-mixed-filters",
		"managed_execution_control_edges.json:fleet-tag-and-id",
		"managed_execution_control_edges.json:fleet-invalid-key",
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var history journal.Storage = journal.NewMemory(nil)
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "audit.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				history = journaldb.New(db)
			}
			s := &Service{recorder: apievents.New(history), clock: clock.Real{}}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region, PrincipalARN: "arn:aws:iam::" + fixture.Account + ":root"})
			var cursor int64
			for _, label := range labels {
				t.Run(strings.ReplaceAll(label, "/", "_"), func(t *testing.T) {
					row, ok := calls[label]
					want := expected[label]
					if !ok || want == nil {
						t.Fatalf("correlated native evidence missing: %s", label)
					}
					input, err := api.NewInput(row.Operation)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(row.Input, input); err != nil {
						t.Fatal(err)
					}
					var output any
					switch row.Operation {
					case "SendCommand":
						output = new(api.SendCommandResult)
					case "CancelCommand":
						output = new(api.CancelCommandResult)
					case "ListCommands":
						output = new(api.ListCommandsResult)
					case "ListCommandInvocations":
						output = new(api.ListCommandInvocationsResult)
					case "GetCommandInvocation":
						output = new(api.GetCommandInvocationResult)
					case "DescribeInstanceInformation":
						output = new(api.DescribeInstanceInformationResult)
					}
					var rejected *awswire.Error
					if row.Code != "Success" {
						rejected = &awswire.Error{Code: row.Code, Message: row.Error.Error.Message, StatusCode: 400}
						output = nil
					} else if err := json.Unmarshal(row.Output, output); err != nil {
						t.Fatal(err)
					}
					before, err := json.Marshal([]any{input, output, rejected})
					if err != nil {
						t.Fatal(err)
					}
					if err := s.record(ctx, row.Operation, input, output, rejected); err != nil {
						t.Fatal(err)
					}
					after, err := json.Marshal([]any{input, output, rejected})
					if err != nil {
						t.Fatal(err)
					}
					if string(before) != string(after) {
						t.Fatal("audit projection mutated public API data")
					}
					events, err := history.Read(ctx, cursor, 2)
					if err != nil || len(events) != 1 {
						t.Fatalf("journal outcome: %v %v", events, err)
					}
					cursor = events[0].Sequence
					raw, err := apievents.CloudTrailRecord(events[0])
					if err != nil {
						t.Fatal(err)
					}
					var got map[string]any
					if err := json.Unmarshal(raw, &got); err != nil {
						t.Fatal(err)
					}
					for _, field := range []string{"eventName", "eventSource", "eventCategory", "readOnly", "requestParameters", "responseElements", "resources", "errorCode", "errorMessage"} {
						if !reflect.DeepEqual(got[field], want[field]) {
							t.Errorf("CloudTrail %s: got %#v want %#v", field, got[field], want[field])
						}
					}
				})
			}
		})
	}
}
