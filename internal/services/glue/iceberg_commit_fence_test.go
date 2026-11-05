package glue_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/services/glue"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
)

// This storage fixture deliberately pauses at the external metadata-write
// boundary. It tests the real Glue/IAM owners, not S3 transport or authorization.
// The root signed REST fixtures cover the actual caller-authorized S3 boundary.
type commitFenceObjects struct {
	files      map[string][]byte
	afterWrite func()
}

func (o *commitFenceObjects) Read(_ context.Context, location string) ([]byte, error) {
	data, exists := o.files[location]
	if !exists {
		return nil, fmt.Errorf("fixture metadata object is absent")
	}
	return bytes.Clone(data), nil
}

func (o *commitFenceObjects) Write(_ context.Context, location string, data []byte) error {
	o.files[location] = bytes.Clone(data)
	if effect := o.afterWrite; effect != nil {
		o.afterWrite = nil
		effect()
	}
	return nil
}

func TestIcebergCommitReauthorizesAndFencesNativeWritesAfterMetadataIO(t *testing.T) {
	for _, scenario := range []string{"revoked-table-authority", "revoked-catalog-authority", "native-version-change", "native-pointer-change", "native-delete-recreate"} {
		t.Run(scenario, func(t *testing.T) {
			const account = "123456789012"
			const namespace = "commit_boundary"
			root := catalogTestContext(account, "us-east-1")
			domain := memory.NewDomain()
			identities := iam.NewMemoryRepository(domain)
			identityService := iam.NewWithConfig(iam.Config{Repository: identities})
			repository := glue.NewMemoryRepository(domain)
			objects := &commitFenceObjects{files: map[string][]byte{}}
			service := glue.New(glue.Config{Repository: repository, Authorizer: authorization.NewWithClock(identityService, nil, nil), IcebergObjects: objects})
			defer service.Close()
			service.JobDriver().Close()
			catalogTestCall[api.CreateDatabaseOutput](t, service, root, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString(namespace))}})
			path := "/iceberg/v1/catalogs/" + account + "/namespaces/" + namespace + "/tables/events"
			call := func(ctx context.Context, method, route string, payload any, want int) []byte {
				t.Helper()
				body, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(method, route, bytes.NewReader(body)).WithContext(ctx)
				response := httptest.NewRecorder()
				service.ServePrivateOperation(response, request)
				if response.Code != want {
					t.Fatalf("%s %s status %d, want %d: %s", method, route, response.Code, want, response.Body.String())
				}
				return response.Body.Bytes()
			}
			created := call(root, http.MethodPost, strings.TrimSuffix(path, "/events"), map[string]any{
				"name": "events", "location": "s3://fixture/commit_boundary/events",
				"schema": map[string]any{"type": "struct", "schema-id": 0, "fields": []any{map[string]any{"id": 1, "name": "id", "required": true, "type": "long"}}},
			}, http.StatusOK)
			var original struct {
				Location string `json:"metadata-location"`
				Metadata struct {
					UUID string `json:"table-uuid"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(created, &original); err != nil || original.Location == "" || original.Metadata.UUID == "" {
				t.Fatalf("create metadata: %s (%v)", created, err)
			}
			oldBytes := bytes.Clone(objects.files[original.Location])
			user := iam.User{UserName: "writer", UserId: "AIDAWRITER", Arn: "arn:aws:iam::" + account + ":user/writer", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
			setPolicy := func(policy string) {
				t.Helper()
				user.IdentityPolicies.Inline["commit"] = policy
				if err := identities.Update(root, func(tx iam.WriteTx) error { return tx.PutUser(iam.Scope{Partition: "aws", AccountID: account}, user) }); err != nil {
					t.Fatal(err)
				}
			}
			setPolicy(`{"Statement":[{"Effect":"Allow","Action":["glue:GetCatalog","glue:UpdateTable"],"Resource":"*"}]}`)
			caller := awsctx.WithMetadata(root, awsctx.Metadata{Partition: "aws", AccountID: account, Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId})
			getInput := &api.GetTableInput{DatabaseName: new(api.NameString(namespace)), Name: new(api.NameString("events"))}
			before := catalogTestCall[api.GetTableOutput](t, service, root, "GetTable", getInput)
			expectedLocation, expectedVersion, expectedDescription := original.Location, "0", ""
			objects.afterWrite = func() {
				switch scenario {
				case "revoked-table-authority":
					setPolicy(`{"Statement":[{"Effect":"Allow","Action":"glue:GetCatalog","Resource":"*"}]}`)
				case "revoked-catalog-authority":
					setPolicy(`{"Statement":[{"Effect":"Allow","Action":"glue:UpdateTable","Resource":"*"}]}`)
				case "native-version-change", "native-pointer-change":
					parameters := api.CloneParametersMap(before.Table.Parameters)
					if scenario == "native-pointer-change" {
						expectedLocation = "s3://fixture/native-replacement.metadata.json"
						parameters["metadata_location"] = api.ParametersMapValue(expectedLocation)
						objects.files[expectedLocation] = bytes.Clone(oldBytes)
					}
					expectedVersion, expectedDescription = "1", "native-writer"
					catalogTestCall[api.UpdateTableOutput](t, service, root, "UpdateTable", &api.UpdateTableInput{DatabaseName: new(api.NameString(namespace)), TableInput: &api.TableInput{Name: new(api.NameString("events")), Description: new(api.DescriptionString(expectedDescription)), Parameters: parameters, TableType: before.Table.TableType, StorageDescriptor: before.Table.StorageDescriptor}})
				case "native-delete-recreate":
					catalogTestCall[api.DeleteTableOutput](t, service, root, "DeleteTable", &api.DeleteTableInput{DatabaseName: new(api.NameString(namespace)), Name: new(api.NameString("events"))})
					expectedLocation = "s3://fixture/new-incarnation.metadata.json"
					parameters := api.CloneParametersMap(before.Table.Parameters)
					parameters["metadata_location"] = api.ParametersMapValue(expectedLocation)
					objects.files[expectedLocation] = bytes.Clone(oldBytes)
					catalogTestCall[api.CreateTableOutput](t, service, root, "CreateTable", &api.CreateTableInput{DatabaseName: new(api.NameString(namespace)), TableInput: &api.TableInput{Name: new(api.NameString("events")), Parameters: parameters, TableType: before.Table.TableType, StorageDescriptor: before.Table.StorageDescriptor}})
				}
			}
			want := http.StatusConflict
			if strings.HasPrefix(scenario, "revoked-") {
				want = http.StatusForbidden
			}
			response := call(caller, http.MethodPost, path, map[string]any{
				"requirements": []any{map[string]any{"type": "assert-table-uuid", "uuid": original.Metadata.UUID}},
				"updates":      []any{map[string]any{"action": "set-properties", "updates": map[string]string{"must-not-publish": scenario}}},
			}, want)
			var failure struct {
				Error struct {
					Type string `json:"type"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response, &failure); err != nil || (want == http.StatusConflict && failure.Error.Type != "CommitFailedException") || (want == http.StatusForbidden && failure.Error.Type != "ForbiddenException") {
				t.Fatalf("commit error: %s (%v)", response, err)
			}
			if objects.afterWrite != nil || len(objects.files) < 2 {
				t.Fatal("fixture did not cross the external metadata write boundary")
			}
			after := catalogTestCall[api.GetTableOutput](t, service, root, "GetTable", getInput)
			if string(*after.Table.VersionId) != expectedVersion || string(after.Table.Parameters["metadata_location"]) != expectedLocation || catalogTestValue(after.Table.Description) != expectedDescription {
				t.Fatalf("losing REST writer published over native/current-IAM state: %+v", after.Table)
			}
			if !bytes.Equal(oldBytes, objects.files[original.Location]) {
				t.Fatal("losing commit modified immutable original metadata")
			}
			var retained struct {
				Properties map[string]string `json:"properties"`
			}
			if err := json.Unmarshal(objects.files[expectedLocation], &retained); err != nil || retained.Properties["must-not-publish"] != "" {
				t.Fatalf("losing metadata became authoritative: %+v (%v)", retained, err)
			}
		})
	}
}
