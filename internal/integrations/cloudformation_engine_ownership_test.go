package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	cacheowner "stackd/internal/services/elasticache"
	memoryowner "stackd/internal/services/memorydb"
	"stackd/storage/sqlite"
	cachestore "stackd/storage/sqlite/elasticache"
	memorystore "stackd/storage/sqlite/memorydb"
)

type cfnEngineFenceHandler interface {
	cloudformation.ResourceHandler
	cloudformation.ResourceCreationRecoverer
	Read(context.Context, cloudformation.ResourceRequest) (cloudformation.Properties, error)
}

// cfnEngineFenceCase drives one registered kind through its real native owner.
// Native commands below run without CloudFormation context, exactly like an
// account-root SDK caller copying public markers or recreating the same name.
type cfnEngineFenceCase struct {
	typ                 string
	h                   cfnEngineFenceHandler
	properties, updated cloudformation.Properties
	tag, remove, create func(context.Context, StepFunctionsCommands, string, map[string]string) error
}

func cfnEngineFenceCases() []cfnEngineFenceCase {
	cacheARN := func(kind string) func(string) string {
		return func(name string) string { return "arn:aws:elasticache:us-east-1:123456789012:" + kind + ":" + name }
	}
	memoryARN := func(kind string) func(string) string {
		return func(name string) string { return "arn:aws:memorydb:us-east-1:123456789012:" + kind + "/" + name }
	}
	cacheTag := func(kind string) func(context.Context, StepFunctionsCommands, string, map[string]string) error {
		return func(ctx context.Context, c StepFunctionsCommands, name string, tags map[string]string) error {
			return cfnComputeRun(ctx, c, "elasticache", "AddTagsToResource", map[string]any{"ResourceName": cacheARN(kind)(name), "Tags": cfnComputeTagList(tags)})
		}
	}
	memoryTag := func(kind string) func(context.Context, StepFunctionsCommands, string, map[string]string) error {
		return func(ctx context.Context, c StepFunctionsCommands, name string, tags map[string]string) error {
			return cfnComputeRun(ctx, c, "memorydb", "TagResource", map[string]any{"ResourceArn": memoryARN(kind)(name), "Tags": cfnComputeTagList(tags)})
		}
	}
	return []cfnEngineFenceCase{
		{typ: "AWS::ElastiCache::ParameterGroup", h: cfnCacheParameterGroup{}, tag: cacheTag("parametergroup"),
			properties: cloudformation.Properties{"CacheParameterGroupFamily": "valkey8", "Description": "owned", "Properties": map[string]any{"timeout": "42"}},
			updated:    cloudformation.Properties{"CacheParameterGroupFamily": "valkey8", "Description": "owned", "Properties": map[string]any{"timeout": "25"}},
			remove: func(ctx context.Context, c StepFunctionsCommands, name string, _ map[string]string) error {
				return cfnComputeRun(ctx, c, "elasticache", "DeleteCacheParameterGroup", map[string]any{"CacheParameterGroupName": name})
			},
			create: func(ctx context.Context, c StepFunctionsCommands, name string, tags map[string]string) error {
				return cfnComputeRun(ctx, c, "elasticache", "CreateCacheParameterGroup", map[string]any{"CacheParameterGroupName": name, "CacheParameterGroupFamily": "valkey8", "Description": "owned", "Tags": cfnComputeTagList(tags)})
			}},
		{typ: "AWS::ElastiCache::User", h: cfnCacheUser{}, tag: cacheTag("user"),
			properties: cloudformation.Properties{"UserId": "fence-cache-user", "UserName": "fence-cache-user", "Engine": "valkey", "AccessString": "on ~* +@all", "NoPasswordRequired": true},
			updated:    cloudformation.Properties{"UserId": "fence-cache-user", "UserName": "fence-cache-user", "Engine": "valkey", "AccessString": "on ~app:* +get", "NoPasswordRequired": true},
			remove: func(ctx context.Context, c StepFunctionsCommands, name string, _ map[string]string) error {
				return cfnComputeRun(ctx, c, "elasticache", "DeleteUser", map[string]any{"UserId": name})
			},
			create: func(ctx context.Context, c StepFunctionsCommands, name string, tags map[string]string) error {
				return cfnComputeRun(ctx, c, "elasticache", "CreateUser", map[string]any{"UserId": name, "UserName": name, "Engine": "valkey", "AccessString": "on ~* +@all", "NoPasswordRequired": true, "Tags": cfnComputeTagList(tags)})
			}},
		{typ: "AWS::MemoryDB::ParameterGroup", h: cfnMemoryParameterGroup{}, tag: memoryTag("parametergroup"),
			properties: cloudformation.Properties{"ParameterGroupName": "fence-memory-params", "Family": "memorydb_valkey7", "Description": "owned"},
			updated:    cloudformation.Properties{"ParameterGroupName": "fence-memory-params", "Family": "memorydb_valkey7", "Description": "owned", "Tags": []any{map[string]any{"Key": "team", "Value": "changed"}}},
			remove: func(ctx context.Context, c StepFunctionsCommands, name string, _ map[string]string) error {
				return cfnComputeRun(ctx, c, "memorydb", "DeleteParameterGroup", map[string]any{"ParameterGroupName": name})
			},
			create: func(ctx context.Context, c StepFunctionsCommands, name string, tags map[string]string) error {
				return cfnComputeRun(ctx, c, "memorydb", "CreateParameterGroup", map[string]any{"ParameterGroupName": name, "Family": "memorydb_valkey7", "Description": "owned", "Tags": cfnComputeTagList(tags)})
			}},
		{typ: "AWS::MemoryDB::ACL", h: cfnMemoryACL{}, tag: memoryTag("acl"),
			properties: cloudformation.Properties{"ACLName": "fence-memory-acl"},
			updated:    cloudformation.Properties{"ACLName": "fence-memory-acl", "Tags": []any{map[string]any{"Key": "team", "Value": "changed"}}},
			remove: func(ctx context.Context, c StepFunctionsCommands, name string, _ map[string]string) error {
				return cfnComputeRun(ctx, c, "memorydb", "DeleteACL", map[string]any{"ACLName": name})
			},
			create: func(ctx context.Context, c StepFunctionsCommands, name string, tags map[string]string) error {
				return cfnComputeRun(ctx, c, "memorydb", "CreateACL", map[string]any{"ACLName": name, "Tags": cfnComputeTagList(tags)})
			}},
	}
}

func cfnEngineFenceHandlerFor(h cfnEngineFenceHandler, c StepFunctionsCommands) cfnEngineFenceHandler {
	switch h.(type) {
	case cfnCacheParameterGroup:
		return cfnCacheParameterGroup{c}
	case cfnCacheUser:
		return cfnCacheUser{c}
	case cfnMemoryParameterGroup:
		return cfnMemoryParameterGroup{c}
	case cfnMemoryACL:
		return cfnMemoryACL{c}
	}
	panic("unregistered fence case")
}

func TestCFNCacheEnginePrivateIncarnationFence(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, tc := range cfnEngineFenceCases() {
				t.Run(tc.typ, func(t *testing.T) {
					ctx := cfnWorkflowOwnerContext(t)
					var cacheRepo cacheowner.Repository = cacheowner.NewMemoryRepository(nil)
					var memoryRepo memoryowner.Repository = memoryowner.NewMemoryRepository(nil)
					var db *sql.DB
					path := filepath.Join(t.TempDir(), "engine.sqlite")
					open := func() {
						var err error
						db, err = sqlite.Open(ctx, path)
						if err != nil {
							t.Fatal(err)
						}
						cacheRepo = cachestore.New(db)
						memoryRepo = memorystore.New(db)
					}
					if backend == "sqlite" {
						open()
						t.Cleanup(func() { _ = db.Close() })
					}
					var cache *cacheowner.Service
					var memory *memoryowner.Service
					var commands StepFunctionsCommands
					var h cfnEngineFenceHandler
					assemble := func() {
						cache = cacheowner.New(cacheowner.Config{Repository: cacheRepo})
						memory = memoryowner.New(memoryowner.Config{Repository: memoryRepo})
						commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"elasticache": cache, "memorydb": memory})
						h = cfnEngineFenceHandlerFor(tc.h, commands)
					}
					assemble()
					t.Cleanup(func() { _ = cache.Close(); _ = memory.Close() })
					r := cfnWorkflowOwnerRequest(tc.typ, "Owned", tc.properties)
					created, err := h.Create(ctx, r)
					if err != nil || created.PhysicalID == "" {
						t.Fatalf("exact incarnation create failed: %+v %v", created, err)
					}
					name := created.PhysicalID
					// A lost Create reply replays the same token and returns the same admitted row.
					replayed, err := h.Create(ctx, r)
					if err != nil || replayed.PhysicalID != name {
						t.Fatalf("same-token replay lost its private claim: %+v %v", replayed, err)
					}
					if backend == "sqlite" {
						if err := cache.Close(); err != nil {
							t.Fatal(err)
						}
						if err := memory.Close(); err != nil {
							t.Fatal(err)
						}
						if err := db.Close(); err != nil {
							t.Fatal(err)
						}
						open()
						assemble()
					}
					recovered, err := h.RecoverCreation(ctx, r)
					if err != nil || recovered.PhysicalID != name {
						t.Fatalf("private claim did not survive reopen: %+v %v", recovered, err)
					}
					r.PhysicalID = name
					observed, err := h.Read(ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					identifier, err := cloudformation.ResourceIdentifier(tc.typ, observed)
					if err != nil || identifier != name {
						t.Fatalf("native projection disagrees with the CloudFormation identifier: %q %v", identifier, err)
					}

					// Copying another incarnation's public markers through native Tag grants it nothing.
					foreign := r
					foreign.Token = "foreign-incarnation"
					if err := tc.tag(ctx, commands, name, cfnComputeOwnedTags(foreign)); err != nil {
						t.Fatal(err)
					}
					// Resolve the collision by physical identity: ParameterGroup's name is a
					// read-only observation, not a template input, and a new token generates a
					// different name when no admitted identity is supplied.
					foreignCreate := foreign
					foreignCreate.PhysicalID = name
					if out, err := h.Create(ctx, foreignCreate); err == nil || out.PhysicalID != "" {
						t.Fatalf("counterfeit markers adopted a foreign row: %+v %v", out, err)
					}
					if out, err := h.RecoverCreation(ctx, foreignCreate); out.PhysicalID != "" || !cfnEngineMissing(err) {
						t.Fatalf("counterfeit markers recovered a foreign row: %+v %v", out, err)
					}
					foreign.Previous = tc.properties
					foreign.Properties = tc.updated
					if _, err := h.Update(ctx, foreign); err == nil {
						t.Fatal("counterfeit markers authorized a foreign update")
					}
					if err := h.Delete(ctx, foreign); err != nil {
						t.Fatalf("stale foreign delete must treat the row as absent: %v", err)
					}
					if _, err := h.RecoverCreation(ctx, r); err != nil {
						t.Fatalf("foreign stack effects touched the exact incarnation: %v", err)
					}
					owned := r
					owned.Previous = tc.properties
					owned.Properties = tc.updated
					if _, err := h.Update(ctx, owned); err != nil {
						t.Fatalf("exact incarnation update rejected: %v", err)
					}

					// Native delete and same-name recreate with copied markers is a new direct-API row.
					if err := tc.remove(ctx, commands, name, nil); err != nil {
						t.Fatal(err)
					}
					if err := tc.create(ctx, commands, name, cfnComputeOwnedTags(r)); err != nil {
						t.Fatal(err)
					}
					if out, err := h.RecoverCreation(ctx, r); out.PhysicalID != "" || !cfnEngineMissing(err) {
						t.Fatalf("recreated row recovered old incarnation: %+v %v", out, err)
					}
					if _, err := h.(cloudformation.ResourceReader).Read(ctx, r); !cfnEngineMissing(err) {
						t.Fatalf("stack read observed a foreign recreated row: %v", err)
					}
					if _, err := h.Update(ctx, owned); err == nil {
						t.Fatal("stale stack updated a foreign recreated row")
					}
					if err := h.Delete(ctx, r); err != nil {
						t.Fatalf("stale stack delete must treat the recreated row as absent: %v", err)
					}
					direct := cloudformation.ResourceRequest{Type: tc.typ, PhysicalID: name, Scope: r.Scope, CloudControl: true}
					if _, err := h.(cloudformation.ResourceReader).Read(ctx, direct); err != nil {
						t.Fatalf("stale stack delete removed a foreign recreated row: %v", err)
					}

					// Cloud Control create claims a new incarnation and never adopts by name.
					cc := cfnWorkflowOwnerRequest(tc.typ, "Resource", tc.properties)
					cc.CloudControl = true
					cc.Token = "cloudcontrol-incarnation"
					cc.PhysicalID = name
					out, err := h.Create(ctx, cc)
					var wire *awswire.Error
					if out.PhysicalID != "" || !errors.As(err, &wire) || wire.Code != "AlreadyExistsException" {
						t.Fatalf("Cloud Control create adopted a same-name row: %+v %v", out, err)
					}
					// Direct Cloud Control mutation uses current IAM, not a request token.
					direct.Previous = tc.properties
					direct.Properties = tc.updated
					if _, err := h.Update(ctx, direct); err != nil {
						t.Fatalf("Cloud Control update of a direct row was fenced by a token: %v", err)
					}
					if err := h.Delete(ctx, direct); err != nil {
						t.Fatal(err)
					}
					if _, err := h.(cloudformation.ResourceReader).Read(ctx, direct); !cfnEngineMissing(err) {
						t.Fatalf("Cloud Control delete left the direct row: %v", err)
					}
					// With no colliding native row, Cloud Control must admit a private claim,
					// replay it, and recover it without a writable generated-name property.
					cc.PhysicalID = ""
					admitted, err := h.Create(ctx, cc)
					if err != nil || admitted.PhysicalID == "" {
						t.Fatalf("Cloud Control fresh admission failed: %+v %v", admitted, err)
					}
					replayed, err = h.Create(ctx, cc)
					if err != nil || replayed.PhysicalID != admitted.PhysicalID {
						t.Fatalf("Cloud Control create replay lost its claim: %+v %v", replayed, err)
					}
					recovered, err = h.RecoverCreation(ctx, cc)
					if err != nil || recovered.PhysicalID != admitted.PhysicalID {
						t.Fatalf("Cloud Control recovery lost its claim: %+v %v", recovered, err)
					}
					cc.PhysicalID = admitted.PhysicalID
					if err := h.Delete(ctx, cc); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}
