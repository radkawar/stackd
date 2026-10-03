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

func TestNativeAdmissionAuditRetainsRejectedRequest(t *testing.T) {
	var audit struct {
		Account, Region string
		SourceFiles     []string `json:"source_files"`
		History         struct {
			Events []struct {
				Label string `json:"call_label"`
				Event map[string]any
			}
		}
	}
	raw, err := os.ReadFile("../../../testdata/aws/ssm/managed_execution_admission_audit.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &audit); err != nil {
		t.Fatal(err)
	}
	type nativeCall struct {
		Label, Code string
		Input       api.SendCommandRequest
		Output      api.SendCommandResult
		Error       struct{ Error struct{ Message string } }
	}
	calls := map[string]nativeCall{}
	for _, file := range audit.SourceFiles {
		var capture struct{ Calls []nativeCall }
		readSizeCapture(t, file, &capture)
		for _, call := range capture.Calls {
			calls[file+":"+call.Label] = call
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var history journal.Storage = journal.NewMemory(nil)
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "admission-audit.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				history = journaldb.New(db)
			}
			s := &Service{recorder: apievents.New(history), clock: clock.Real{}}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: audit.Account, Region: audit.Region})
			var cursor int64
			for _, captured := range audit.History.Events {
				t.Run(strings.ReplaceAll(captured.Label, "/", "_"), func(t *testing.T) {
					call, ok := calls[captured.Label]
					if !ok {
						t.Fatal("native correlated request missing")
					}
					var rejected *awswire.Error
					if call.Code != "Success" {
						rejected = &awswire.Error{Code: call.Code, Message: call.Error.Error.Message, StatusCode: 400}
					}
					if err := s.record(ctx, "SendCommand", &call.Input, &call.Output, rejected); err != nil {
						t.Fatal(err)
					}
					events, err := history.Read(ctx, cursor, 2)
					if err != nil || len(events) != 1 {
						t.Fatalf("audit history: %v %v", events, err)
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
						if !reflect.DeepEqual(got[field], captured.Event[field]) {
							t.Errorf("CloudTrail %s: got %#v want %#v", field, got[field], captured.Event[field])
						}
					}
				})
			}
		})
	}
}
