package eks_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/eks"
	"stackd/journal"
)

type auditRecorder struct {
	calls []journal.APICallCompleted
}

func (r *auditRecorder) Record(_ context.Context, _ journal.Envelope, call journal.APICallCompleted) error {
	r.calls = append(r.calls, call)
	return nil
}

func TestNativeManagementAudit(t *testing.T) {
	var fixture struct {
		Calls []struct {
			Label, Operation, Code string
			Input                  json.RawMessage
			RequestID              string `json:"request_id"`
		}
		History struct {
			Events []struct {
				Event struct {
					RequestID, EventName, EventSource, ErrorCode, ErrorMessage string
					ReadOnly, ManagementEvent                                  bool
					RequestParameters, ResponseElements                        json.RawMessage
				}
			}
		}
	}
	body, err := os.ReadFile("../../../testdata/aws/eks/management_audit.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	model, _ := awscatalog.LookupService("eks")
	for _, nativeCall := range fixture.Calls {
		t.Run(nativeCall.Label, func(t *testing.T) {
			recorder := &auditRecorder{}
			service := eks.New(eks.Config{Recorder: recorder})
			t.Cleanup(func() { _ = service.Close() })
			input, err := awscommands.NewInput("eks", nativeCall.Operation)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(nativeCall.Input, input); err != nil {
				t.Fatal(err)
			}
			operation, ok := model.Operation(nativeCall.Operation)
			if !ok {
				t.Fatal("missing generated operation", nativeCall.Operation)
			}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
			_, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: input})
			code := "Success"
			if rejected != nil {
				code = rejected.Code
			}
			if code != nativeCall.Code {
				t.Fatalf("operation outcome = %s, native = %s", code, nativeCall.Code)
			}
			if len(recorder.calls) != 1 {
				t.Fatalf("committed records = %d, want one", len(recorder.calls))
			}
			local := recorder.calls[0]
			for _, row := range fixture.History.Events {
				native := row.Event
				if native.RequestID != nativeCall.RequestID {
					continue
				}
				if local.EventName != native.EventName || local.EventSource != native.EventSource || local.ReadOnly != native.ReadOnly || (local.Category == journal.CategoryManagement) != native.ManagementEvent {
					t.Fatalf("management classification differs: %+v", local)
				}
				if local.ErrorCode != native.ErrorCode || local.ErrorMessage != native.ErrorMessage {
					t.Fatalf("error field presence differs: local=%q/%q native=%q/%q", local.ErrorCode, local.ErrorMessage, native.ErrorCode, native.ErrorMessage)
				}
				for _, field := range []struct {
					name             string
					actual, expected json.RawMessage
				}{{"requestParameters", local.RequestParameters, native.RequestParameters}, {"responseElements", local.ResponseElements, native.ResponseElements}} {
					var actual, expected any
					if len(field.actual) != 0 {
						if err := json.Unmarshal(field.actual, &actual); err != nil {
							t.Fatal(err)
						}
					}
					if len(field.expected) != 0 {
						if err := json.Unmarshal(field.expected, &expected); err != nil {
							t.Fatal(err)
						}
					}
					if !reflect.DeepEqual(actual, expected) {
						t.Fatalf("%s: local=%s native=%s", field.name, field.actual, field.expected)
					}
				}
				return
			}
			t.Fatal("no exact native request-ID audit record")
		})
	}
}
