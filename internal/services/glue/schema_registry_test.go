package glue_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/glue"
	"stackd/storage/sqlite"
	gluesqlite "stackd/storage/sqlite/glue"
)

func registryContext(account, region string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: region, PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account})
}
func registryExecute(s *glue.Service, ctx context.Context, action string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("glue")
	operation, _ := model.Operation(action)
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: awscatalog.AWSJSON11, Input: input})
}
func registryCall[O any](t *testing.T, s *glue.Service, ctx context.Context, action string, input any) *O {
	t.Helper()
	out, err := registryExecute(s, ctx, action, input)
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	typed, ok := out.(*O)
	if !ok {
		t.Fatalf("%s output %T", action, out)
	}
	return typed
}
func registryError(t *testing.T, s *glue.Service, ctx context.Context, action string, input any, code string) {
	t.Helper()
	_, err := registryExecute(s, ctx, action, input)
	if err == nil || err.Code != code {
		t.Fatalf("%s error=%v, want %s", action, err, code)
	}
}

// These transitions follow the native registry captures and the documented
// reader/writer rules: https://docs.aws.amazon.com/glue/latest/dg/schema-registry.html.
func TestSchemaRegistryEvolutionMetadataScopeAndDeletion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := registryContext("123456789012", "us-east-1")
			c := clock.NewManual(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC))
			var repository glue.Repository
			var closeDB func()
			var reopen func() glue.Repository
			if backend == "memory" {
				repository = glue.NewMemoryRepository(nil)
				reopen = func() glue.Repository { return repository }
				closeDB = func() {}
			} else {
				path := filepath.Join(t.TempDir(), "registry.sqlite")
				open := func() glue.Repository {
					db, err := sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					closeDB = func() {
						if err := db.Close(); err != nil {
							t.Error(err)
						}
					}
					return gluesqlite.New(db)
				}
				repository = open()
				reopen = open
			}
			s := glue.New(glue.Config{Repository: repository, Clock: c})
			t.Cleanup(func() { _ = s.Close(); closeDB() })
			rid := &api.RegistryId{RegistryName: new(api.SchemaRegistryNameString("evolution"))}
			sid := &api.SchemaId{RegistryName: rid.RegistryName, SchemaName: new(api.SchemaRegistryNameString("Item"))}
			registryCall[api.CreateRegistryResponse](t, s, ctx, "CreateRegistry", &api.CreateRegistryInput{RegistryName: rid.RegistryName})
			base := api.SchemaDefinitionString(`{"type":"record","name":"Item","fields":[{"name":"value","type":"int"}]}`)
			create := &api.CreateSchemaInput{RegistryId: rid, SchemaName: sid.SchemaName, DataFormat: new(api.DataFormatAVRO), SchemaDefinition: &base}
			registryError(t, s, ctx, "CreateSchema", create, "InvalidInputException")
			create.Compatibility = new(api.CompatibilityBACKWARD)
			first := registryCall[api.CreateSchemaResponse](t, s, ctx, "CreateSchema", create)
			compatible := api.SchemaDefinitionString(`{"type":"record","name":"Item","fields":[{"name":"value","type":"long"},{"name":"extra","type":["null","string"],"default":null}]}`)
			second := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: sid, SchemaDefinition: &compatible})
			if *second.VersionNumber != 2 || *second.SchemaVersionId == *first.SchemaVersionId {
				t.Fatalf("version allocation: %+v", second)
			}
			invalid := api.SchemaDefinitionString(`{"type":"record","name":"Item","fields":[{"name":"required","type":"string"}]}`)
			failed := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: sid, SchemaDefinition: &invalid})
			if *failed.Status != api.SchemaVersionStatusFAILURE || *failed.VersionNumber != 3 {
				t.Fatalf("incompatible version was not retained as FAILURE: %+v", failed)
			}
			retained := registryCall[api.GetSchemaVersionResponse](t, s, ctx, "GetSchemaVersion", &api.GetSchemaVersionInput{SchemaVersionId: failed.SchemaVersionId})
			if *retained.Status != api.SchemaVersionStatusFAILURE || *retained.SchemaDefinition != invalid {
				t.Fatalf("failed definition lost: %+v", retained)
			}
			duplicate := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: sid, SchemaDefinition: &compatible})
			if *duplicate.SchemaVersionId != *second.SchemaVersionId || *duplicate.VersionNumber != 2 {
				t.Fatalf("duplicate allocated a version: %+v", duplicate)
			}
			for _, v := range []string{"z-first", "a-second"} {
				registryCall[api.PutSchemaVersionMetadataResponse](t, s, ctx, "PutSchemaVersionMetadata", &api.PutSchemaVersionMetadataInput{SchemaVersionId: second.SchemaVersionId, MetadataKeyValue: &api.MetadataKeyValuePair{MetadataKey: new(api.MetadataKeyString("source")), MetadataValue: new(api.MetadataValueString(v))}})
			}
			registryError(t, s, ctx, "PutSchemaVersionMetadata", &api.PutSchemaVersionMetadataInput{SchemaVersionId: second.SchemaVersionId, MetadataKeyValue: &api.MetadataKeyValuePair{MetadataKey: new(api.MetadataKeyString("source")), MetadataValue: new(api.MetadataValueString("z-first"))}}, "AlreadyExistsException")
			metadata := registryCall[api.QuerySchemaVersionMetadataResponse](t, s, ctx, "QuerySchemaVersionMetadata", &api.QuerySchemaVersionMetadataInput{SchemaVersionId: second.SchemaVersionId})
			source := metadata.MetadataInfoMap["source"]
			if source.MetadataValue == nil || *source.MetadataValue != "a-second" || len(source.OtherMetadataValueList) != 1 || *source.OtherMetadataValueList[0].MetadataValue != "z-first" {
				t.Fatalf("multivalue metadata ordering lost: %+v", source)
			}
			page := registryCall[api.ListSchemaVersionsResponse](t, s, ctx, "ListSchemaVersions", &api.ListSchemaVersionsInput{SchemaId: sid, MaxResults: new(api.MaxResultsNumber(1))})
			if len(page.Schemas) != 1 || *page.Schemas[0].VersionNumber != 2 || page.NextToken == nil {
				t.Fatalf("version page order: %+v", page)
			}
			last := registryCall[api.ListSchemaVersionsResponse](t, s, ctx, "ListSchemaVersions", &api.ListSchemaVersionsInput{SchemaId: sid, NextToken: page.NextToken})
			if len(last.Schemas) != 2 || *last.Schemas[0].VersionNumber != 1 || *last.Schemas[1].VersionNumber != 3 || *last.Schemas[1].Status != api.SchemaVersionStatusFAILURE || last.NextToken != nil {
				t.Fatalf("version continuation: %+v", last)
			}
			for _, other := range []context.Context{registryContext("999999999999", "us-east-1"), registryContext("123456789012", "eu-west-1")} {
				registryError(t, s, other, "GetSchemaVersion", &api.GetSchemaVersionInput{SchemaVersionId: second.SchemaVersionId}, "EntityNotFoundException")
			}
			// A newly installed deny on the ancestor registry must be observed before
			// mutation, even though the request selects a schema.
			if err := repository.Update(ctx, func(tx glue.Transaction) error {
				return tx.PutResourcePolicy(glue.ResourcePolicyRecord{Scope: glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Policy: authorization.BoundPolicy{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"glue:RegisterSchemaVersion","Resource":"arn:aws:glue:us-east-1:123456789012:registry/evolution"}}`}})
			}); err != nil {
				t.Fatal(err)
			}
			registryError(t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: sid, SchemaDefinition: &compatible}, "AccessDeniedException")
			if err := repository.Update(ctx, func(tx glue.Transaction) error {
				return tx.PutResourcePolicy(glue.ResourcePolicyRecord{Scope: glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Policy: authorization.BoundPolicy{}})
			}); err != nil {
				t.Fatal(err)
			}
			registryError(t, s, ctx, "DeleteSchemaVersions", &api.DeleteSchemaVersionsInput{SchemaId: sid, Versions: new(api.VersionsString("1"))}, "InvalidInputException")
			registryCall[api.DeleteSchemaVersionsResponse](t, s, ctx, "DeleteSchemaVersions", &api.DeleteSchemaVersionsInput{SchemaId: sid, Versions: new(api.VersionsString("2"))})
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			closeDB()
			repository = reopen()
			s = glue.New(glue.Config{Repository: repository, Clock: c})
			c.Advance(2 * time.Second)
			if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
				t.Fatal(err)
			}
			registryError(t, s, ctx, "GetSchemaVersion", &api.GetSchemaVersionInput{SchemaVersionId: second.SchemaVersionId}, "EntityNotFoundException")
			registryError(t, s, ctx, "QuerySchemaVersionMetadata", &api.QuerySchemaVersionMetadataInput{SchemaVersionId: second.SchemaVersionId}, "EntityNotFoundException")
			third := registryCall[api.RegisterSchemaVersionResponse](t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: sid, SchemaDefinition: &compatible})
			if *third.VersionNumber != 4 || *third.SchemaVersionId == *second.SchemaVersionId {
				t.Fatalf("deleted version reused: %+v", third)
			}
			registryCall[api.DeleteRegistryResponse](t, s, ctx, "DeleteRegistry", &api.DeleteRegistryInput{RegistryId: rid})
			registryError(t, s, ctx, "RegisterSchemaVersion", &api.RegisterSchemaVersionInput{SchemaId: sid, SchemaDefinition: &base}, "ConcurrentModificationException")
			c.Advance(2 * time.Second)
			if _, err := s.JobDriver().RunDue(ctx, 10); err != nil {
				t.Fatal(err)
			}
			registryError(t, s, ctx, "GetSchema", &api.GetSchemaInput{SchemaId: sid}, "EntityNotFoundException")
			registryError(t, s, ctx, "GetRegistry", &api.GetRegistryInput{RegistryId: rid}, "EntityNotFoundException")
		})
	}
}

func TestRegistryNativeSchemaValidity(t *testing.T) {
	ctx := registryContext("123456789012", "us-east-1")
	s := glue.New(glue.Config{})
	t.Cleanup(func() { _ = s.Close() })
	for _, name := range []string{"registry.json", "registry_complete.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "aws", "glue", name))
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Observations []struct {
				Label, Operation string
				Input            json.RawMessage
				Result           struct {
					Code   string
					Output struct{ Valid *bool }
				}
			}
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		for _, observation := range fixture.Observations {
			if observation.Operation != "check-schema-version-validity" {
				continue
			}
			t.Run(name+"/"+observation.Label, func(t *testing.T) {
				var in api.CheckSchemaVersionValidityInput
				if err := json.Unmarshal(observation.Input, &in); err != nil {
					t.Fatal(err)
				}
				if observation.Result.Code != "Success" {
					registryError(t, s, ctx, "CheckSchemaVersionValidity", &in, observation.Result.Code)
					return
				}
				out := registryCall[api.CheckSchemaVersionValidityResponse](t, s, ctx, "CheckSchemaVersionValidity", &in)
				if observation.Result.Output.Valid == nil || out.Valid == nil || bool(*out.Valid) != *observation.Result.Output.Valid {
					t.Fatalf("validity differs: %+v, native %+v", out, observation.Result.Output)
				}
				if !bool(*out.Valid) && (out.Error == nil || *out.Error == "") {
					t.Fatal("invalid schema lacks diagnostic")
				}
			})
		}
	}
}

// Create-with-tags requires TagResource, and parent-registry tags are evaluated
// on every schema creation, independently from the schema's requested tags.
func TestRegistryCreationTagAuthorization(t *testing.T) {
	ctx := registryContext("123456789012", "us-east-1")
	repository := glue.NewMemoryRepository(nil)
	s := glue.New(glue.Config{Repository: repository})
	t.Cleanup(func() { _ = s.Close() })
	setPolicy := func(document string) {
		t.Helper()
		if err := repository.Update(ctx, func(tx glue.Transaction) error {
			return tx.PutResourcePolicy(glue.ResourcePolicyRecord{Scope: glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Policy: authorization.BoundPolicy{Document: document}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	setPolicy(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"glue:TagResource","Resource":"*"}}`)
	rid := &api.RegistryId{RegistryName: new(api.SchemaRegistryNameString("tag-policy"))}
	createRegistry := &api.CreateRegistryInput{RegistryName: rid.RegistryName, Tags: api.TagsMap{"access": "open"}}
	registryError(t, s, ctx, "CreateRegistry", createRegistry, "AccessDeniedException")
	createRegistry.Tags = nil
	registry := registryCall[api.CreateRegistryResponse](t, s, ctx, "CreateRegistry", createRegistry)
	createSchema := &api.CreateSchemaInput{RegistryId: rid, SchemaName: new(api.SchemaRegistryNameString("Item")), DataFormat: new(api.DataFormatAVRO), Compatibility: new(api.CompatibilityNONE), SchemaDefinition: new(api.SchemaDefinitionString(`{"type":"record","name":"Item","fields":[]}`)), Tags: api.TagsMap{"access": "open"}}
	registryError(t, s, ctx, "CreateSchema", createSchema, "AccessDeniedException")
	createSchema.Tags = nil
	registryCall[api.CreateSchemaResponse](t, s, ctx, "CreateSchema", createSchema)
	setPolicy(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"glue:CreateSchema","Resource":"arn:aws:glue:us-east-1:123456789012:registry/tag-policy","Condition":{"StringEquals":{"aws:ResourceTag/access":"blocked"}}}}`)
	registryCall[api.TagResourceResponse](t, s, ctx, "TagResource", &api.TagResourceInput{ResourceArn: registry.RegistryArn, TagsToAdd: api.TagsMap{"access": "blocked"}})
	createSchema.SchemaName = new(api.SchemaRegistryNameString("Denied"))
	registryError(t, s, ctx, "CreateSchema", createSchema, "AccessDeniedException")
	registryCall[api.TagResourceResponse](t, s, ctx, "TagResource", &api.TagResourceInput{ResourceArn: registry.RegistryArn, TagsToAdd: api.TagsMap{"access": "open"}})
	registryCall[api.CreateSchemaResponse](t, s, ctx, "CreateSchema", createSchema)
}
