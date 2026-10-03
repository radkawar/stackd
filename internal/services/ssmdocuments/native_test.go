package ssmdocuments_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/services/ssmdocuments"
	"stackd/storage/sqlite"
	dbdocuments "stackd/storage/sqlite/ssmdocuments"
)

type nativeDocumentCall struct {
	Label, Service, Operation, Code string
	Input, Output                   json.RawMessage
}

func rootContext(ctx context.Context) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
}
func TestNativeDocumentVersionAndAdmissionReplay(t *testing.T) {
	var calls []nativeDocumentCall
	for _, name := range []string{"managed_execution_documents.json", "managed_execution_document_history.json", "managed_execution_document_schema.json"} {
		data, err := os.ReadFile("../../../testdata/aws/ssm/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct{ Calls []nativeDocumentCall }
		if err = json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, fixture.Calls...)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var db *sql.DB
			var repo ssmdocuments.Repository
			if backend == "sqlite" {
				var err error
				db, err = sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "documents.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				repo = dbdocuments.New(db)
			}
			service := ssmdocuments.New(ssmdocuments.Config{Repository: repo})
			defer service.Close()
			ctx := rootContext(t.Context())
			for _, row := range calls {
				if row.Service != "ssm" || row.Code == "ThrottlingException" {
					continue
				}
				supported := false
				for _, op := range service.Operations() {
					if op == row.Operation {
						supported = true
					}
				}
				if !supported {
					continue
				}
				// Native calls observe settled state between accepted mutations.
				if _, err := service.JobDriver().RunDue(ctx, 100); err != nil {
					t.Fatal(err)
				}
				request, err := api.DecodeRequest(row.Operation, awsapi.Request{JSON: row.Input})
				if err != nil {
					t.Fatalf("%s decode: %v", row.Label, err)
				}
				output, rejected := service.ExecuteCommand(ctx, request)
				if row.Code != "Success" {
					if rejected == nil || rejected.Code != row.Code {
						t.Fatalf("%s error: %v want %s", row.Label, rejected, row.Code)
					}
					continue
				}
				if rejected != nil {
					t.Fatalf("%s: %v", row.Label, rejected)
				}
				body, err := json.Marshal(output)
				if err != nil {
					t.Fatal(err)
				}
				var got, want map[string]any
				if err = json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(row.Output, &want); err != nil {
					t.Fatal(err)
				}
				switch row.Operation {
				case "CreateDocument", "UpdateDocument":
					assertDocumentFields(t, row.Label, got["DocumentDescription"], want["DocumentDescription"])
				case "DescribeDocument":
					assertDocumentFields(t, row.Label, got["Document"], want["Document"])
				case "GetDocument":
					for _, key := range []string{"Name", "DocumentVersion", "DocumentFormat", "DocumentType", "Status"} {
						if got[key] != want[key] {
							t.Fatalf("%s %s got %v want %v", row.Label, key, got[key], want[key])
						}
					}
					if got["DocumentFormat"] == "JSON" && got["Content"] != want["Content"] {
						t.Fatalf("%s raw source changed", row.Label)
					}
				case "ListDocumentVersions":
					normalizeVersions := func(v any) any {
						for _, raw := range v.([]any) {
							row := raw.(map[string]any)
							delete(row, "CreatedDate")
						}
						return v
					}
					if !reflect.DeepEqual(normalizeVersions(got["DocumentVersions"]), normalizeVersions(want["DocumentVersions"])) {
						t.Fatalf("%s versions got %v want %v", row.Label, got, want)
					}
				}
			}
		})
	}
}
func assertDocumentFields(t *testing.T, label string, actual, expected any) {
	t.Helper()
	got, want := actual.(map[string]any), expected.(map[string]any)
	for _, key := range []string{"Name", "Owner", "DocumentVersion", "DefaultVersion", "LatestVersion", "Hash", "HashType", "DocumentFormat", "DocumentType", "SchemaVersion", "VersionName", "Status"} {
		if got[key] != want[key] {
			t.Fatalf("%s %s got %v want %v", label, key, got[key], want[key])
		}
	}
	parameters := func(v any) map[string]any {
		out := map[string]any{}
		if v != nil {
			for _, item := range v.([]any) {
				row := item.(map[string]any)
				out[row["Name"].(string)] = row
			}
		}
		return out
	}
	if !reflect.DeepEqual(parameters(got["Parameters"]), parameters(want["Parameters"])) {
		t.Fatalf("%s parameters got %v want %v", label, got["Parameters"], want["Parameters"])
	}
}
func TestAgentDocumentParametersAndYAML(t *testing.T) {
	service := ssmdocuments.New(ssmdocuments.Config{})
	defer service.Close()
	ctx := rootContext(t.Context())
	builtin, err := service.Resolve(ctx, "AWS-RunShellScript", "")
	if err != nil {
		t.Fatal(err)
	}
	values, err := ssmdocuments.ValidateParameters(builtin, map[string][]string{"commands": {"printf 'one\\n'", "exit 7"}})
	if err != nil {
		t.Fatal(err)
	}
	if values["executionTimeout"][0] != "3600" || builtin.MainSteps[0].Name != "aws:runShellScript" || builtin.SchemaVersion != "1.2" {
		t.Fatalf("native shell resolution: %+v %+v", builtin, values)
	}
	duration, err := ssmdocuments.ExecutionTimeout(builtin, values)
	if err != nil || duration != time.Hour {
		t.Fatalf("execution budget: %v %v", duration, err)
	}
	for _, values := range []map[string][]string{{}, {"commands": {}}, {"commands": {"echo"}, "executionTimeout": {"0"}}, {"commands": {"echo"}, "unexpected": {"x"}}} {
		if _, err = ssmdocuments.ValidateParameters(builtin, values); err == nil {
			t.Fatalf("invalid parameters accepted: %v", values)
		}
	}
	source := "schemaVersion: '2.2'\nparameters:\n  Message:\n    type: String\n    default: 'literal $HOME'\n    interpolationType: ENV_VAR\nmainSteps:\n  - action: aws:runShellScript\n    name: shell\n    inputs:\n      runCommand:\n        - 'printf %s \"$SSM_Message\"'\n"
	input, _ := json.Marshal(map[string]string{"Name": "YamlCommand", "Content": source, "DocumentFormat": "YAML"})
	request, err := api.DecodeRequest("CreateDocument", awsapi.Request{JSON: input})
	if err != nil {
		t.Fatal(err)
	}
	if _, rejected := service.ExecuteCommand(ctx, request); rejected != nil {
		t.Fatal(rejected)
	}
	doc, err := service.Resolve(ctx, "YamlCommand", "1")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := ssmdocuments.JSONContent(doc)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Content != source || !json.Valid(agent) || !strings.Contains(string(agent), "$SSM_Message") || doc.Parameters["Message"].InterpolationType != "ENV_VAR" {
		t.Fatalf("source/interpolation changed: %s", agent)
	}
}

func TestNativeDeliveryExpiryIgnoresOmittedParameterDefaults(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/ssm/managed_execution_document_expiry.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Calls []nativeDocumentCall }
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	service := ssmdocuments.New(ssmdocuments.Config{})
	defer service.Close()
	ctx := rootContext(t.Context())
	for _, row := range fixture.Calls {
		if row.Code != "Success" {
			continue
		}
		switch row.Operation {
		case "CreateDocument":
			request, err := api.DecodeRequest(row.Operation, awsapi.Request{JSON: row.Input})
			if err != nil {
				t.Fatal(err)
			}
			if _, rejected := service.ExecuteCommand(ctx, request); rejected != nil {
				t.Fatal(rejected)
			}
		case "SendCommand":
			var input struct {
				DocumentName   string
				TimeoutSeconds int
				Parameters     map[string][]string
			}
			var output struct {
				Command struct{ ExpiresAfter, RequestedDateTime time.Time }
			}
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(row.Output, &output); err != nil {
				t.Fatal(err)
			}
			document, err := service.Resolve(ctx, input.DocumentName, "")
			if err != nil {
				t.Fatal(err)
			}
			execution, err := ssmdocuments.ExecutionTimeout(document, input.Parameters)
			if err != nil {
				t.Fatal(err)
			}
			got := execution + time.Duration(input.TimeoutSeconds)*time.Second
			want := output.Command.ExpiresAfter.Sub(output.Command.RequestedDateTime)
			if got != want {
				t.Fatalf("%s delivery expiry = %v, native %v", row.Label, got, want)
			}
		}
	}
}
