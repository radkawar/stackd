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

	"gopkg.in/yaml.v3"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/services/ssmdocuments"
	"stackd/storage/sqlite"
	dbdocuments "stackd/storage/sqlite/ssmdocuments"
)

type configurationPolicies struct{ schemaARN string }

func (p configurationPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:*","Resource":"*"},{"Effect":"Deny","Action":"ssm:GetDocument","Resource":"` + p.schemaARN + `"}]}`}}}, nil
}

// The native source includes schema denial at CreateDocument, independent
// UpdateDocument/GetDocument authority, numeric dependency pinning, forced
// deletion and same-content recreation. Replay it against both real stores.
func TestApplicationConfigurationNativeDependencies(t *testing.T) {
	replayAppConfigDocuments(t, "application_configuration_documents.json")
}

func TestDeploymentStrategyNativeDocuments(t *testing.T) {
	replayAppConfigDocuments(t, "deployment_strategy_documents.json")
}

func replayAppConfigDocuments(t *testing.T, fixture string) {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/ssm/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Calls []struct {
			nativeDocumentCall
			Authority string
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	var schemaName string
	for _, row := range capture.Calls {
		if row.Label == "schema-create" {
			var in struct{ Name string }
			if err := json.Unmarshal(row.Input, &in); err != nil {
				t.Fatal(err)
			}
			schemaName = in.Name
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var db *sql.DB
			var repo ssmdocuments.Repository
			path := filepath.Join(t.TempDir(), "configurations.db")
			open := func() {
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					repo = dbdocuments.New(db)
				}
			}
			open()
			defer func() {
				if db != nil {
					_ = db.Close()
				}
			}()
			authorizer := authorization.New(configurationPolicies{"arn:aws:ssm:us-east-1:000000000000:document/" + schemaName}, nil)
			service := ssmdocuments.New(ssmdocuments.Config{Repository: repo, Authorizer: authorizer})
			defer func() { _ = service.Close() }()
			root := rootContext(t.Context())
			metadata := awsctx.FromContext(root)
			metadata.PrincipalARN = "arn:aws:iam::000000000000:role/configuration-reader"
			metadata.PrincipalID = "AROACONFIGURATION"
			restricted := awsctx.WithMetadata(t.Context(), metadata)
			for _, row := range capture.Calls {
				if row.Code == "ThrottlingException" {
					continue
				}
				if _, err := service.JobDriver().RunDue(root, 100); err != nil {
					t.Fatal(err)
				}
				if backend == "sqlite" && (row.Label == "config-update-valid" || row.Label == "strategy-update") {
					_ = service.Close()
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					open()
					service = ssmdocuments.New(ssmdocuments.Config{Repository: repo, Authorizer: authorizer})
				}
				ctx := root
				if row.Authority != "" {
					ctx = restricted
				}
				request, err := api.DecodeRequest(row.Operation, awsapi.Request{JSON: row.Input})
				if err != nil {
					t.Fatalf("%s decode: %v", row.Label, err)
				}
				output, rejected := service.ExecuteCommand(ctx, request)
				if row.Code != "Success" {
					if rejected == nil || rejected.Code != row.Code {
						t.Fatalf("%s: got %v, want %s", row.Label, rejected, row.Code)
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
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(row.Output, &want); err != nil {
					t.Fatal(err)
				}
				switch row.Operation {
				case "CreateDocument", "UpdateDocument":
					got, want = got["DocumentDescription"].(map[string]any), want["DocumentDescription"].(map[string]any)
					assertDocumentFields(t, row.Label, got, want)
				case "DescribeDocument":
					got, want = got["Document"].(map[string]any), want["Document"].(map[string]any)
					assertDocumentFields(t, row.Label, got, want)
				case "GetDocument":
					for _, key := range []string{"Name", "DocumentType", "DocumentVersion", "DocumentFormat"} {
						if got[key] != want[key] {
							t.Fatalf("%s %s: got %v, want %v", row.Label, key, got[key], want[key])
						}
					}
					if strings.Contains(row.Label, "get-yaml") || row.Label == "get-config-yaml-json" {
						var actual, expected any
						if err := yaml.Unmarshal([]byte(got["Content"].(string)), &actual); err != nil {
							t.Fatal(err)
						}
						if err := yaml.Unmarshal([]byte(want["Content"].(string)), &expected); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(actual, expected) {
							t.Fatalf("%s converted content: got %v, want %v", row.Label, actual, expected)
						}
					} else if got["Content"] != want["Content"] {
						t.Fatalf("%s changed immutable source bytes", row.Label)
					}
				}
				if expected, ok := want["Requires"].([]any); ok && len(expected) > 0 && !reflect.DeepEqual(got["Requires"], expected) {
					t.Fatalf("%s dependency: got %v, want %v", row.Label, got["Requires"], expected)
				}
			}
		})
	}
}
