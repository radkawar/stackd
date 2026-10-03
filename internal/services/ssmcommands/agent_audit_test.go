package ssmcommands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/journal"
	"stackd/storage/sqlite"
	journaldb "stackd/storage/sqlite/journal"
)

func TestNativeAgentHeartbeatAuditProjection(t *testing.T) {
	var fixture struct {
		Account, Region string
		History         struct {
			Events []struct{ Event map[string]any }
		}
	}
	raw, err := os.ReadFile("../../../testdata/aws/ssm/managed_execution_audit.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	// Native agent health has three independently observed field-presence shapes.
	// Repeated pings do not add a distinct consumer-visible boundary.
	expected := map[string]map[string]any{}
	for _, row := range fixture.History.Events {
		if row.Event["eventName"] != "UpdateInstanceInformation" {
			continue
		}
		request := row.Event["requestParameters"].(map[string]any)
		var keys []string
		for key := range request {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		expected[strings.Join(keys, ",")] = row.Event
	}
	if len(expected) != 3 {
		t.Fatalf("native heartbeat field-presence cases: %d", len(expected))
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var history journal.Storage = journal.NewMemory(nil)
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "heartbeat-audit.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				history = journaldb.New(db)
			}
			s := &Service{recorder: apievents.New(history), clock: clock.Real{}}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region})
			var cursor int64
			for name, want := range expected {
				t.Run(name, func(t *testing.T) {
					request, err := json.Marshal(want["requestParameters"])
					if err != nil {
						t.Fatal(err)
					}
					var input UpdateInstanceInformationInput
					if err := json.Unmarshal(request, &input); err != nil {
						t.Fatal(err)
					}
					if input.IPAddress != nil {
						input.IPAddress = new("10.193.1.23")
					}
					if err := s.recordAgentHealth(ctx, input, nil); err != nil {
						t.Fatal(err)
					}
					events, err := history.Read(ctx, cursor, 2)
					if err != nil || len(events) != 1 {
						t.Fatalf("heartbeat journal: %v %v", events, err)
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
					if input.IPAddress != nil && *input.IPAddress != "10.193.1.23" {
						t.Fatal("audit changed the health request")
					}
				})
			}
		})
	}
}
