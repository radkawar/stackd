package pipes

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/pipes"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
	"stackd/storage/memory"
)

// Audit field names, sensitive leaves, mutation responses and read/error
// omissions are public observability contracts, replayed from captured native
// CloudTrail rather than snapshots of this implementation.
func TestNativePipesManagementObservation(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/scheduler_pipes/lifecycle_success.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Calls []struct {
			RequestID  string          `json:"request_id"`
			Parameters json.RawMessage `json:"parameters"`
			Output     json.RawMessage `json:"output"`
		} `json:"calls"`
		CloudTrail struct {
			Events []struct {
				Event struct {
					Source    string          `json:"eventSource"`
					Name      string          `json:"eventName"`
					RequestID string          `json:"requestID"`
					Request   json.RawMessage `json:"requestParameters"`
					Response  json.RawMessage `json:"responseElements"`
					ErrorCode string          `json:"errorCode"`
					ReadOnly  bool            `json:"readOnly"`
				} `json:"event"`
			} `json:"events"`
		} `json:"cloudtrail"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.CloudTrail.Events {
		native := row.Event
		if native.Source != "pipes.amazonaws.com" {
			continue
		}
		t.Run(native.Name+"/"+native.RequestID, func(t *testing.T) {
			var inputJSON, outputJSON json.RawMessage
			for _, call := range fixture.Calls {
				if call.RequestID == native.RequestID {
					inputJSON, outputJSON = call.Parameters, call.Output
					break
				}
			}
			if inputJSON == nil {
				t.Fatal("native request ID lacks its paired SDK input")
			}
			input, err := api.NewInput(native.Name)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(inputJSON, input); err != nil {
				t.Fatal(err)
			}
			var output any
			switch native.Name {
			case "CreatePipe":
				output = new(api.CreatePipeOutput)
			case "UpdatePipe":
				output = new(api.UpdatePipeOutput)
			case "StartPipe":
				output = new(api.StartPipeOutput)
			case "StopPipe":
				output = new(api.StopPipeOutput)
			case "DeletePipe":
				output = new(api.DeletePipeOutput)
			}
			if output != nil && outputJSON != nil {
				if err = json.Unmarshal(outputJSON, output); err != nil {
					t.Fatal(err)
				}
			}
			var rejected *awswire.Error
			if native.ErrorCode != "" {
				rejected = failure(native.ErrorCode, "native rejection", 400)
				if native.ErrorCode == "ConflictException" {
					name := value(input.(*api.CreatePipeInput).Name)
					rejected.Message = "Pipe " + name + " already exists."
					id, _ := json.Marshal(name)
					rejected.Details = map[string]json.RawMessage{"resourceId": id, "resourceType": json.RawMessage(`"Pipe"`)}
				}
			}
			domain := memory.NewDomain()
			history := journal.NewMemory(domain)
			service := NewWithConfig(Config{Repository: NewMemoryRepository(domain), Recorder: apievents.New(history)})
			defer service.Close()
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"})
			if err = service.recordCall(ctx, native.Name, input, output, rejected); err != nil {
				t.Fatal(err)
			}
			entries, err := history.Read(ctx, 0, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].APICallCompleted == nil {
				t.Fatal("management completion missing")
			}
			actual := entries[0].APICallCompleted
			canonical := func(raw json.RawMessage) any {
				if len(raw) == 0 {
					return nil
				}
				var out any
				if err := json.Unmarshal(raw, &out); err != nil {
					t.Fatal(err)
				}
				if fields, ok := out.(map[string]any); ok {
					delete(fields, "CreationTime")
					delete(fields, "LastModifiedTime")
				}
				return out
			}
			if !reflect.DeepEqual(canonical(actual.RequestParameters), canonical(native.Request)) {
				t.Fatalf("native request projection differs: want %s, got %s", native.Request, actual.RequestParameters)
			}
			if !reflect.DeepEqual(canonical(actual.ResponseElements), canonical(native.Response)) {
				t.Fatalf("native response projection differs: want %s, got %s", native.Response, actual.ResponseElements)
			}
			if actual.ReadOnly != native.ReadOnly || actual.ErrorCode != native.ErrorCode || actual.ErrorMessage != "" || len(actual.Resources) != 0 {
				t.Fatalf("native management classification differs: %#v", actual)
			}
		})
	}
}
