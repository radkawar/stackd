package ec2

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/journal"
)

// SDK results and independently collected CloudTrail records are different
// native contracts. This checks their production projection, not guest execution.
func TestNativeSuccessfulLaunchAudit(t *testing.T) {
	readFixture := func(path string, target any) {
		t.Helper()
		body, err := os.ReadFile("../../../testdata/aws/ec2/" + path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, target); err != nil {
			t.Fatal(err)
		}
	}
	var fixture struct {
		Calls []struct {
			Source, Label string
			RequestID     string `json:"request_id"`
			Input, Output json.RawMessage
		}
	}
	readFixture("public_addresses_launch_projection.json", &fixture)
	var audit struct {
		Account, Region string
		History         struct {
			Events []struct {
				Event struct {
					RequestID                           string
					RequestParameters, ResponseElements any
				}
			}
		}
	}
	readFixture("public_addresses_lifecycle_audit.json", &audit)
	for _, call := range fixture.Calls {
		t.Run(call.Source+":"+call.Label, func(t *testing.T) {
			var input api.RunInstancesRequest
			var output api.Reservation
			if err := json.Unmarshal(call.Input, &input); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(call.Output, &output); err != nil {
				t.Fatal(err)
			}
			history := journal.NewMemory(nil)
			service := New(Config{Recorder: apievents.New(history)})
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: audit.Account, Region: audit.Region, RequestID: call.RequestID, PrincipalARN: "arn:aws:iam::" + audit.Account + ":root", PrincipalID: audit.Account})
			if err := service.recordCall(ctx, "RunInstances", &input, &output, nil); err != nil {
				t.Fatal(err)
			}
			entries, err := history.Read(ctx, 0, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].APICallCompleted == nil {
				t.Fatalf("missing launch audit outcome: %+v", entries)
			}
			for _, row := range audit.History.Events {
				if row.Event.RequestID != call.RequestID {
					continue
				}
				for _, pair := range []struct {
					name     string
					actual   json.RawMessage
					expected any
				}{
					{"request", entries[0].APICallCompleted.RequestParameters, row.Event.RequestParameters},
					{"response", entries[0].APICallCompleted.ResponseElements, row.Event.ResponseElements},
				} {
					var got any
					if err := json.Unmarshal(pair.actual, &got); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, pair.expected) {
						want, _ := json.MarshalIndent(pair.expected, "", "  ")
						actual, _ := json.MarshalIndent(got, "", "  ")
						t.Errorf("native launch %s mismatch:\ngot %s\nwant %s", pair.name, actual, want)
					}
				}
				return
			}
			t.Fatal("missing exact-request native successful launch audit")
		})
	}
}
