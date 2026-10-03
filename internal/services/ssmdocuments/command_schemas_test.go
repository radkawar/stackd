package ssmdocuments_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/services/ssmdocuments"
)

// Replay observed admission, including legacy property lists/objects, plugin ids,
// ignored legacy preconditions, parameter interpolation and schema-specific errors.
func TestNativeCommandSchemaAdmission(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/ssm/stackd-ssm-schema-668d4554581f.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Calls []struct {
			Label, Operation string
			Input            json.RawMessage
			Error            struct{ Code string }
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Calls {
		if row.Operation != "create_document" || row.Error.Code == "ThrottlingException" {
			continue
		}
		t.Run(row.Label, func(t *testing.T) {
			service := ssmdocuments.New(ssmdocuments.Config{})
			defer service.Close()
			request, err := api.DecodeRequest("CreateDocument", awsapi.Request{JSON: row.Input})
			if err != nil {
				t.Fatal(err)
			}
			_, rejected := service.ExecuteCommand(rootContext(t.Context()), request)
			if row.Error.Code != "" {
				if rejected == nil || rejected.Code != row.Error.Code {
					t.Fatalf("got %v want %s", rejected, row.Error.Code)
				}
				return
			}
			if rejected != nil {
				t.Fatal(rejected)
			}
		})
	}
}

func TestCommandSchemaPluginIdentityAndDeliveryExpiry(t *testing.T) {
	for _, row := range []struct {
		name, schema, body string
		budget             time.Duration
		plugins            []string
	}{
		{"legacy-list", "1.2", `"runtimeConfig":{"aws:runShellScript":{"properties":[{"id":"first","runCommand":["printf first"],"timeoutSeconds":"5"},{"id":"second","runCommand":["exit 7"],"timeoutSeconds":"70"}]}}`, 5 * time.Second, []string{"aws:runShellScript"}},
		{"legacy-object", "1.2", `"runtimeConfig":{"aws:runShellScript":{"properties":{"runCommand":["printf object"],"timeoutSeconds":19}}}`, 19 * time.Second, []string{"aws:runShellScript"}},
		{"legacy-empty", "1.2", `"runtimeConfig":{"aws:runShellScript":{"properties":[]}}`, time.Hour, []string{"aws:runShellScript"}},
		{"modern-sequence", "2.0", `"mainSteps":[{"action":"aws:runShellScript","name":"first","inputs":{"runCommand":["printf first"],"timeoutSeconds":"5"}},{"action":"aws:runShellScript","name":"second","inputs":{"runCommand":["exit 7"],"timeoutSeconds":"70"}}]`, 75 * time.Second, []string{"first", "second"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			service := ssmdocuments.New(ssmdocuments.Config{})
			defer service.Close()
			ctx := rootContext(t.Context())
			content := `{"schemaVersion":"` + row.schema + `",` + row.body + `}`
			input, _ := json.Marshal(map[string]string{"Name": "SchemaPlan", "Content": content})
			request, err := api.DecodeRequest("CreateDocument", awsapi.Request{JSON: input})
			if err != nil {
				t.Fatal(err)
			}
			if _, rejected := service.ExecuteCommand(ctx, request); rejected != nil {
				t.Fatal(rejected)
			}
			if _, err = service.JobDriver().RunDue(ctx, 100); err != nil {
				t.Fatal(err)
			}
			doc, err := service.Resolve(ctx, "SchemaPlan", "")
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.MainSteps) != len(row.plugins) {
				t.Fatalf("property ids became invocation plugins: %+v", doc.MainSteps)
			}
			for i, name := range row.plugins {
				if doc.MainSteps[i].Name != name {
					t.Fatalf("plugin %d: %+v", i, doc.MainSteps[i])
				}
			}
			budget, err := ssmdocuments.ExecutionTimeout(doc, nil)
			if err != nil || budget != row.budget {
				t.Fatalf("delivery budget %v %v want %v", budget, err, row.budget)
			}
			payload, err := ssmdocuments.JSONContent(doc)
			if err != nil || string(payload) != content {
				t.Fatalf("agent source rewritten: %s %v", payload, err)
			}
		})
	}
}
