package ssmdocuments

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	dbjournal "stackd/storage/sqlite/journal"
)

// Replay native DTOs and bind CloudTrail's private document identity to a real
// incarnation record. Initial lifecycle statuses remain part of the contract.
func TestNativeDocumentAuditProjection(t *testing.T) {
	var fixture struct {
		History struct {
			Events []struct {
				Label string `json:"call_label"`
				Event struct {
					Name         string                     `json:"eventName"`
					Source       string                     `json:"eventSource"`
					Category     string                     `json:"eventCategory"`
					ReadOnly     bool                       `json:"readOnly"`
					Request      json.RawMessage            `json:"requestParameters"`
					Response     json.RawMessage            `json:"responseElements"`
					Resources    []journal.APIEventResource `json:"resources"`
					ErrorCode    string                     `json:"errorCode"`
					ErrorMessage string                     `json:"errorMessage"`
				} `json:"event"`
			} `json:"events"`
		} `json:"history"`
	}
	readDocumentAuditFixture(t, "managed_execution_audit.json", &fixture)
	type sourceCall struct {
		Label, Operation, Code string
		Input, Output          json.RawMessage
		Error                  struct {
			Error struct{ Code, Message string }
		}
	}
	calls := map[string]sourceCall{}
	for _, name := range []string{"managed_execution_document_history.json", "managed_execution_document_schema.json"} {
		var source struct{ Calls []sourceCall }
		readDocumentAuditFixture(t, name, &source)
		for _, call := range source.Calls {
			calls[name+":"+call.Label] = call
		}
	}
	labels := []string{
		"document-create", "document-create-duplicate", "document-invalid-malformed",
		"document-update-version-one-throttle-retry", "document-unchanged-omitted",
		"document-unchanged-latest", "document-duplicate-version-name-throttle-retry-throttle-retry",
		"document-update-version-one", // Captured frontend throttle: no parameters.
		"document-default-two", "document-default-missing",
		"document-get_document-None", "document-get_document-999", "document-get-version-name", "document-get-yaml",
		"document-describe_document-None", "document-preflight", "document-describe_document-999",
		"document-list-owned", "document-versions",
		"document-delete-version-one", "document-delete-default-version", "document-delete-absent",
	}
	for i := range labels {
		labels[i] = "managed_execution_document_history.json:" + labels[i]
	}
	labels = append(labels, "managed_execution_document_schema.json:schema-create-arbitrary-literal-timeout-throttle-retry")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var history journal.Storage = journal.NewMemory(memory.NewDomain())
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "audit.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				history = dbjournal.New(db)
			}
			service := New(Config{Recorder: apievents.New(history)})
			t.Cleanup(func() { _ = service.Close() })
			bindings := map[string]Record{}
			nativeIDs := map[string]string{}
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"})
			var after int64
			for _, label := range labels {
				t.Run(label, func(t *testing.T) {
					var nativeIndex = -1
					for i, row := range fixture.History.Events {
						if row.Label == label {
							nativeIndex = i
							break
						}
					}
					if nativeIndex < 0 {
						t.Fatal("positive native audit missing")
					}
					native := fixture.History.Events[nativeIndex].Event
					source, ok := calls[label]
					if !ok || source.Operation != native.Name {
						t.Fatal("correlated source call missing")
					}
					request, err := api.DecodeRequest(source.Operation, awsapi.Request{JSON: source.Input})
					if err != nil {
						t.Fatal(err)
					}
					input := request.Input
					var output any
					switch source.Operation {
					case "CreateDocument":
						output = new(api.CreateDocumentResult)
					case "UpdateDocument":
						output = new(api.UpdateDocumentResult)
					case "UpdateDocumentDefaultVersion":
						output = new(api.UpdateDocumentDefaultVersionResult)
					case "GetDocument":
						output = new(api.GetDocumentResult)
					case "DescribeDocument":
						output = new(api.DescribeDocumentResult)
					case "ListDocuments":
						output = new(api.ListDocumentsResult)
					case "ListDocumentVersions":
						output = new(api.ListDocumentVersionsResult)
					case "DeleteDocument":
						output = new(api.DeleteDocumentResult)
					}
					var rejected *awswire.Error
					if source.Code != "Success" {
						rejected = failure(source.Error.Error.Code, source.Error.Error.Message)
					} else if err = json.Unmarshal(source.Output, output); err != nil {
						t.Fatal(err)
					}
					documentID := ""
					wantResponse := native.Response
					if rejected == nil && (source.Operation == "CreateDocument" || source.Operation == "UpdateDocument") {
						var response map[string]any
						if err := json.Unmarshal(native.Response, &response); err != nil {
							t.Fatal(err)
						}
						description := response["documentDescription"].(map[string]any)
						id := description["documentId"].(string)
						parsed, err := uuid.Parse(id)
						if err != nil || parsed.Version() != 4 {
							t.Fatalf("native document identity is not UUIDv4: %s", id)
						}
						name := description["name"].(string)
						if previous, ok := nativeIDs[name]; ok && previous != id {
							t.Fatal("native incarnation changed during version updates")
						}
						nativeIDs[name] = id
						record, ok := bindings[id]
						if !ok {
							record = Record{Key: Key{Scope: scopeFor(ctx), Name: name}, Type: "Command", DocumentID: uuid.NewString(), DefaultVersion: 1, LatestVersion: 1, NextVersion: 2}
							bindings[id] = record
							if err := service.repository.Update(ctx, func(tx Transaction) error { return tx.PutDocument(record) }); err != nil {
								t.Fatal(err)
							}
						}
						documentID = record.DocumentID
						description["documentId"] = documentID
						wantResponse, err = json.Marshal(response)
						if err != nil {
							t.Fatal(err)
						}
					}
					beforeInput, _ := json.Marshal(input)
					beforeOutput, _ := json.Marshal(output)
					if err = service.record(ctx, source.Operation, input, output, rejected, documentID); err != nil {
						t.Fatal(err)
					}
					entries, err := history.Read(ctx, after, 1)
					if err != nil {
						t.Fatal(err)
					}
					if len(entries) != 1 || entries[0].APICallCompleted == nil {
						t.Fatal("audit completion missing")
					}
					after = entries[0].Sequence
					actual := entries[0].APICallCompleted
					if actual.EventName != native.Name || actual.EventSource != native.Source || string(actual.Category) != native.Category || actual.ReadOnly != native.ReadOnly {
						t.Fatalf("classification differs: %#v", actual)
					}
					if actual.ErrorCode != native.ErrorCode || actual.ErrorMessage != native.ErrorMessage {
						t.Fatalf("native error lost: %s %s", actual.ErrorCode, actual.ErrorMessage)
					}
					if !reflect.DeepEqual(actual.EventResources, native.Resources) || len(actual.Resources) != 0 {
						t.Fatalf("unexpected document resource rows: %#v", actual.EventResources)
					}
					canonical := func(raw json.RawMessage) any {
						if len(raw) == 0 {
							return nil
						}
						var value any
						if err := json.Unmarshal(raw, &value); err != nil {
							t.Fatal(err)
						}
						return value
					}
					if !reflect.DeepEqual(canonical(actual.RequestParameters), canonical(native.Request)) {
						t.Fatalf("request got %s want %s", actual.RequestParameters, native.Request)
					}
					if !reflect.DeepEqual(canonical(actual.ResponseElements), canonical(wantResponse)) {
						t.Fatalf("response got %s want %#v", actual.ResponseElements, wantResponse)
					}
					afterInput, _ := json.Marshal(input)
					afterOutput, _ := json.Marshal(output)
					if string(beforeInput) != string(afterInput) || string(beforeOutput) != string(afterOutput) {
						t.Fatal("audit changed public input/output data")
					}
				})
			}
		})
	}
}

func readDocumentAuditFixture(t *testing.T, name string, out any) {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/ssm/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}
