package appconfig_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/appconfig"
	"stackd/storage/sqlite"
	dbappconfig "stackd/storage/sqlite/appconfig"
)

func TestNativeExtensionVersionsAndAssociations(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/appconfig/extensions_native.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Rows []struct {
			Label  string
			Output json.RawMessage
			Error  struct{ Error struct{ Code string } }
		}
	}
	if err = json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	nativeVersions := map[string]int32{}
	nativeErrors := map[string]string{}
	for _, row := range capture.Rows {
		var out struct{ VersionNumber int32 }
		if err = json.Unmarshal(row.Output, &out); err != nil && len(row.Output) != 0 {
			t.Fatal(err)
		}
		nativeVersions[row.Label] = out.VersionNumber
		nativeErrors[row.Label] = row.Error.Error.Code
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repo appconfig.Repository
			if backend == "memory" {
				repo = appconfig.NewMemoryRepository(nil)
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "extensions.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = dbappconfig.New(db)
			}
			service := appconfig.New(appconfig.Config{Repository: repo})
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
			call := func(action string, input any) (any, *awswire.Error) {
				model, _ := awscatalog.LookupService("appconfig")
				op, _ := model.Operation(action)
				return service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
			}
			must := func(action string, input any) any {
				t.Helper()
				out, rejected := call(action, input)
				if rejected != nil {
					t.Fatalf("%s: %v", action, rejected)
				}
				return out
			}
			reject := func(action string, input any, label string) {
				t.Helper()
				_, wire := call(action, input)
				if wire == nil || wire.Code != nativeErrors[label] {
					t.Fatalf("%s: got %v, native %s", label, wire, nativeErrors[label])
				}
			}
			actions := api.ActionsMap{api.ActionPointPRE_CREATE_HOSTED_CONFIGURATION_VERSION: {{Name: new(api.Name("capture")), Uri: new(api.Uri("arn:aws:lambda:us-east-1:000000000000:function:extension"))}}}
			parameters := api.ParameterMap{"fixed": {Required: new(api.Boolean(true))}, "dynamic": {Dynamic: new(api.Boolean(true))}}
			create := &api.CreateExtensionInput{Name: new(api.ExtensionOrParameterName("native-extension")), Actions: actions, Parameters: parameters}
			first := must("CreateExtension", create).(*api.Extension)
			same := must("CreateExtension", create).(*api.Extension)
			if *first.Id != *same.Id || int32(*same.VersionNumber) != nativeVersions["same-name-next-version"] {
				t.Fatalf("idempotent create: first=%+v same=%+v", first, same)
			}
			changed := *create
			changed.Description = new(api.Description("changed"))
			reject("CreateExtension", &changed, "same-name-changed-no-latest")
			changed.LatestVersionNumber = new(api.Integer(1))
			second := must("CreateExtension", &changed).(*api.Extension)
			if int32(*second.VersionNumber) != nativeVersions["stale-latest-version"] || *second.Id != *first.Id {
				t.Fatalf("new version: %+v", second)
			}
			changed.Description = new(api.Description("again"))
			reject("CreateExtension", &changed, "stale-latest-conflict")
			bad := *create
			bad.Name = new(api.ExtensionOrParameterName("invalid"))
			bad.Parameters = api.ParameterMap{"invalid": {Required: new(api.Boolean(true)), Dynamic: new(api.Boolean(true))}}
			reject("CreateExtension", &bad, "dynamic-required-invalid")
			updated := must("UpdateExtension", &api.UpdateExtensionInput{ExtensionIdentifier: new(api.Identifier(*first.Id)), VersionNumber: new(api.Integer(1)), Description: new(api.Description("updated-one"))}).(*api.Extension)
			if *updated.VersionNumber != 1 || *updated.Description != "updated-one" {
				t.Fatalf("update must keep version: %+v", updated)
			}
			reject("UpdateExtension", &api.UpdateExtensionInput{ExtensionIdentifier: new(api.Identifier(*first.Id)), Actions: api.ActionsMap{}}, "empty-actions")
			reject("GetExtension", &api.GetExtensionInput{ExtensionIdentifier: new(api.Identifier(*first.Arn)), VersionNumber: new(api.Integer(2))}, "version-arn-conflict")
			app := must("CreateApplication", &api.CreateApplicationInput{Name: new(api.Name("extension-app"))}).(*api.Application)
			resource := "arn:aws:appconfig:us-east-1:000000000000:application/" + string(*app.Id)
			associationInput := &api.CreateExtensionAssociationInput{ExtensionIdentifier: new(api.Identifier(*first.Id)), ExtensionVersionNumber: new(api.Integer(1)), ResourceIdentifier: new(api.Identifier(resource))}
			reject("CreateExtensionAssociation", associationInput, "required-missing-v1")
			associationInput.Parameters = api.ParameterValueMap{"fixed": "one", "dynamic": "default"}
			association := must("CreateExtensionAssociation", associationInput).(*api.ExtensionAssociation)
			duplicate := must("CreateExtensionAssociation", associationInput).(*api.ExtensionAssociation)
			if *duplicate.Id == *association.Id {
				t.Fatal("native duplicate associations must retain independent IDs")
			}
			reject("DeleteExtension", &api.DeleteExtensionInput{ExtensionIdentifier: new(api.Identifier(*first.Id)), VersionNumber: new(api.Integer(1))}, "delete-in-use")
			reject("UpdateExtensionAssociation", &api.UpdateExtensionAssociationInput{ExtensionAssociationId: new(api.Id(*association.Id)), Parameters: api.ParameterValueMap{"dynamic": "second"}}, "update-merge-or-replace")
			_ = service.Close()
			service = appconfig.New(appconfig.Config{Repository: repo})
			defer service.Close()
			restored := must("GetExtensionAssociation", &api.GetExtensionAssociationInput{ExtensionAssociationId: new(api.Id(*association.Id))}).(*api.ExtensionAssociation)
			if restored.Parameters["fixed"] != "one" || restored.Parameters["dynamic"] != "default" || *restored.ExtensionVersionNumber != 1 {
				t.Fatalf("association restart: %+v", restored)
			}
			other := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "999999999999", Region: "us-east-1", PrincipalARN: "arn:aws:iam::999999999999:root", PrincipalID: "999999999999"})
			saved := ctx
			ctx = other
			_, wire := call("GetExtensionAssociation", &api.GetExtensionAssociationInput{ExtensionAssociationId: new(api.Id(*association.Id))})
			ctx = saved
			if wire == nil || wire.Code != "ResourceNotFoundException" {
				t.Fatalf("association scope isolation: %v", wire)
			}
			for _, id := range []*api.Identifier{association.Id, duplicate.Id} {
				must("DeleteExtensionAssociation", &api.DeleteExtensionAssociationInput{ExtensionAssociationId: new(api.Id(*id))})
			}
			must("DeleteExtension", &api.DeleteExtensionInput{ExtensionIdentifier: new(api.Identifier(*first.Id))})
			remaining := must("GetExtension", &api.GetExtensionInput{ExtensionIdentifier: new(api.Identifier(*first.Id))}).(*api.Extension)
			if int32(*remaining.VersionNumber) != nativeVersions["get-after-delete-all"] {
				t.Fatalf("delete latest must retain v1: %+v", remaining)
			}
			listed := must("ListExtensions", &api.ListExtensionsInput{Name: new(api.QueryName("extension"))}).(*api.Extensions)
			if len(listed.Items) != 0 {
				t.Fatalf("native name filter is exact: %+v", listed)
			}
		})
	}
}
