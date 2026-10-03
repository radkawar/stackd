package glue_test

import (
	"encoding/json"
	"testing"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
)

// Primary examples distinguish closed/open JSON objects and proto2 required
// fields: https://docs.aws.amazon.com/glue/latest/dg/schema-registry.html.
func TestRegistryFormatCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name          string
		format        api.DataFormat
		mode          api.Compatibility
		before, after string
		status        api.SchemaVersionStatus
	}{
		{"avro-promotion", api.DataFormatAVRO, api.CompatibilityBACKWARD, `{"type":"record","name":"R","fields":[{"name":"v","type":"int"}]}`, `{"type":"record","name":"R","fields":[{"name":"v","type":"long"}]}`, api.SchemaVersionStatusAVAILABLE},
		{"avro-forward-promotion", api.DataFormatAVRO, api.CompatibilityFORWARD, `{"type":"record","name":"R","fields":[{"name":"v","type":"int"}]}`, `{"type":"record","name":"R","fields":[{"name":"v","type":"long"}]}`, api.SchemaVersionStatusFAILURE},
		{"json-closed-add", api.DataFormatJSON, api.CompatibilityBACKWARD, `{"type":"object","properties":{"v":{"type":"string"}},"additionalProperties":false}`, `{"type":"object","properties":{"v":{"type":"string"},"note":{"type":"string"}},"additionalProperties":false}`, api.SchemaVersionStatusAVAILABLE},
		{"json-open-add", api.DataFormatJSON, api.CompatibilityBACKWARD, `{"type":"object","properties":{"v":{"type":"string"}}}`, `{"type":"object","properties":{"v":{"type":"string"},"note":{"type":"string"}}}`, api.SchemaVersionStatusFAILURE},
		{"json-numeric-bound", api.DataFormatJSON, api.CompatibilityBACKWARD, `{"type":"integer","minimum":9007199254740992}`, `{"type":"integer","minimum":9007199254740993}`, api.SchemaVersionStatusFAILURE},
		{"proto-required-add", api.DataFormatPROTOBUF, api.CompatibilityBACKWARD, `syntax="proto2";message Item {optional string value=1;}`, `syntax="proto2";message Item {optional string value=1;required string added=2;}`, api.SchemaVersionStatusFAILURE},
		{"proto-optional-add", api.DataFormatPROTOBUF, api.CompatibilityBACKWARD, `syntax="proto3";message Item {string value=1;}`, `syntax="proto3";message Item {string value=1;string added=2;}`, api.SchemaVersionStatusAVAILABLE},
		{"proto-remove-rpc", api.DataFormatPROTOBUF, api.CompatibilityBACKWARD, `syntax="proto3";message Item {string value=1;}service API {rpc Read(Item) returns (Item);}`, `syntax="proto3";message Item {string value=1;}`, api.SchemaVersionStatusFAILURE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := registryContext("123456789012", "us-east-1")
			s := glue.New(glue.Config{})
			t.Cleanup(func() { _ = s.Close() })
			created := registryCall[api.CreateSchemaResponse](t, s, ctx, "CreateSchema", &api.CreateSchemaInput{SchemaName: new(api.SchemaRegistryNameString("sample")), DataFormat: &tc.format, Compatibility: &tc.mode, SchemaDefinition: new(api.SchemaDefinitionString(tc.before))})
			out := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: &api.SchemaId{SchemaArn: created.SchemaArn}, SchemaDefinition: new(api.SchemaDefinitionString(tc.after))})
			if *out.Status != tc.status || *out.VersionNumber != 2 || *out.SchemaVersionId == *created.SchemaVersionId {
				t.Fatalf("evolution=%+v, want status %s and a distinct version2", out, tc.status)
			}
		})
	}
}

func TestRegistryCheckpointAndDisabledEvolution(t *testing.T) {
	ctx := registryContext("123456789012", "us-east-1")
	s := glue.New(glue.Config{})
	t.Cleanup(func() { _ = s.Close() })
	one := api.SchemaDefinitionString(`{"type":"record","name":"R","fields":[{"name":"v","type":"int"}]}`)
	two := api.SchemaDefinitionString(`{"type":"record","name":"R","fields":[{"name":"v","type":"string"}]}`)
	three := api.SchemaDefinitionString(`{"type":"record","name":"R","fields":[{"name":"v","type":"string"},{"name":"note","type":["null","string"],"default":null}]}`)
	created := registryCall[api.CreateSchemaResponse](t, s, ctx, "CreateSchema", &api.CreateSchemaInput{SchemaName: new(api.SchemaRegistryNameString("checkpoint")), DataFormat: new(api.DataFormatAVRO), Compatibility: new(api.CompatibilityNONE), SchemaDefinition: &one})
	id := &api.SchemaId{SchemaArn: created.SchemaArn}
	registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: id, SchemaDefinition: &two})
	registryCall[api.UpdateSchemaResponse](t, s, ctx, "UpdateSchema", &api.UpdateSchemaInput{SchemaId: id, Compatibility: new(api.CompatibilityBACKWARD_ALL), SchemaVersionNumber: &api.SchemaVersionNumber{VersionNumber: new(api.VersionLongNumber(2))}})
	out := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: id, SchemaDefinition: &three})
	if *out.Status != api.SchemaVersionStatusAVAILABLE {
		t.Fatalf("checkpoint incorrectly compared pre-checkpoint version: %+v", out)
	}
	registryCall[api.UpdateSchemaResponse](t, s, ctx, "UpdateSchema", &api.UpdateSchemaInput{SchemaId: id, Compatibility: new(api.CompatibilityDISABLED), SchemaVersionNumber: &api.SchemaVersionNumber{LatestVersion: new(api.LatestSchemaVersionBoolean(true))}})
	registryError(t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: id, SchemaDefinition: new(api.SchemaDefinitionString(`{"type":"record","name":"R","fields":[]}`))}, "InvalidInputException")
}

func TestRegistrySyntaxDiffPreservesJSONPatchValues(t *testing.T) {
	ctx := registryContext("123456789012", "us-east-1")
	s := glue.New(glue.Config{})
	t.Cleanup(func() { _ = s.Close() })
	one := api.SchemaDefinitionString(`{"type":"record","name":"Item","fields":[{"name":"value","type":"int"}]}`)
	two := api.SchemaDefinitionString(`{"type":"record","name":"Item","fields":[{"name":"value","type":"int"},{"name":"note","type":["null","string"],"default":null}]}`)
	created := registryCall[api.CreateSchemaResponse](t, s, ctx, "CreateSchema", &api.CreateSchemaInput{SchemaName: new(api.SchemaRegistryNameString("diff")), DataFormat: new(api.DataFormatAVRO), Compatibility: new(api.CompatibilityBACKWARD), SchemaDefinition: &one})
	id := &api.SchemaId{SchemaArn: created.SchemaArn}
	registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: id, SchemaDefinition: &two})
	diff := registryCall[api.GetSchemaVersionsDiffResponse](t, s, ctx, "GetSchemaVersionsDiff", &api.GetSchemaVersionsDiffInput{SchemaId: id, SchemaDiffType: new(api.SchemaDiffTypeSYNTAX_DIFF), FirstSchemaVersionNumber: &api.SchemaVersionNumber{VersionNumber: new(api.VersionLongNumber(1))}, SecondSchemaVersionNumber: &api.SchemaVersionNumber{VersionNumber: new(api.VersionLongNumber(2))}})
	var patch []struct {
		Op, Path string
		Value    map[string]json.RawMessage
	}
	if err := json.Unmarshal([]byte(*diff.Diff), &patch); err != nil {
		t.Fatal(err)
	}
	if len(patch) != 1 || patch[0].Op != "add" || patch[0].Path != "/fields/1" || string(patch[0].Value["default"]) != "null" || string(patch[0].Value["name"]) != `"note"` {
		t.Fatalf("native-compatible field addition patch=%s", *diff.Diff)
	}
}

// registry_boundaries.json establishes that *_ALL does not prohibit deleting
// noncheckpoint versions, and LatestVersion skips a more recent failed version.
func TestRegistryNativeAllModeBoundaries(t *testing.T) {
	for _, mode := range []api.Compatibility{api.CompatibilityBACKWARD_ALL, api.CompatibilityFULL_ALL} {
		t.Run(string(mode), func(t *testing.T) {
			ctx := registryContext("123456789012", "us-east-1")
			s := glue.New(glue.Config{})
			t.Cleanup(func() { _ = s.Close() })
			one := api.SchemaDefinitionString(`{"type":"record","name":"R","fields":[{"name":"v","type":"int"}]}`)
			two := api.SchemaDefinitionString(`{"type":"record","name":"R","fields":[{"name":"v","type":"int"},{"name":"note","type":["null","string"],"default":null}]}`)
			bad := api.SchemaDefinitionString(`{"type":"record","name":"R","fields":[{"name":"v","type":"string"}]}`)
			created := registryCall[api.CreateSchemaResponse](t, s, ctx, "CreateSchema", &api.CreateSchemaInput{SchemaName: new(api.SchemaRegistryNameString("all-mode")), DataFormat: new(api.DataFormatAVRO), Compatibility: &mode, SchemaDefinition: &one})
			id := &api.SchemaId{SchemaArn: created.SchemaArn}
			second := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: id, SchemaDefinition: &two})
			failed := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: id, SchemaDefinition: &bad})
			repeated := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: id, SchemaDefinition: &bad})
			if *failed.Status != api.SchemaVersionStatusFAILURE || *failed.SchemaVersionId != *repeated.SchemaVersionId || *repeated.VersionNumber != 3 {
				t.Fatalf("failed-version idempotency changed: %+v %+v", failed, repeated)
			}
			latest := registryCall[api.GetSchemaVersionResponse](t, s, ctx, "GetSchemaVersion", &api.GetSchemaVersionInput{SchemaId: id, SchemaVersionNumber: &api.SchemaVersionNumber{LatestVersion: new(api.LatestSchemaVersionBoolean(true))}})
			schema := registryCall[api.GetSchemaResponse](t, s, ctx, "GetSchema", &api.GetSchemaInput{SchemaId: id})
			if *latest.SchemaVersionId != *second.SchemaVersionId || *schema.LatestSchemaVersion != 3 || *schema.NextSchemaVersion != 4 {
				t.Fatalf("latest available/allocation distinction lost: %+v %+v", latest, schema)
			}
			deleted := registryCall[api.DeleteSchemaVersionsResponse](t, s, ctx, "DeleteSchemaVersions", &api.DeleteSchemaVersionsInput{SchemaId: id, Versions: new(api.VersionsString("2"))})
			if len(deleted.SchemaVersionErrors) != 0 {
				t.Fatalf("native permits deleting noncheckpoint version under %s: %+v", mode, deleted)
			}
		})
	}
}
