package integrations

import (
	"path/filepath"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	owner "stackd/internal/services/elasticache"
	"stackd/storage/sqlite"
	cachestore "stackd/storage/sqlite/elasticache"
	"strings"
	"testing"
)

func TestCloudFormationCacheParameterRemovalUsesOwnerReplacement(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
			var repository owner.Repository = owner.NewMemoryRepository(nil)
			if backend == "sqlite" {
				db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "parameters.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repository = cachestore.New(db)
			}
			service := owner.New(owner.Config{Repository: repository})
			t.Cleanup(func() { _ = service.Close() })
			h := cfnCacheParameterGroup{commands: NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"elasticache": service})}
			original := cloudformation.Properties{"Description": "real native parameter owner", "CacheParameterGroupFamily": "valkey8", "Properties": map[string]any{"timeout": "42", "tcp-keepalive": "99"}}
			r := cloudformation.ResourceRequest{StackID: "parameter-stack", LogicalID: "Parameters", Token: "parameter-incarnation", Properties: original}
			if err := h.Validate(cloudformation.Properties{"CacheParameterGroupName": "stale-api-name", "Description": "real native parameter owner", "CacheParameterGroupFamily": "valkey8"}); err == nil {
				t.Fatal("native API name was admitted as a writable CloudFormation property")
			}
			created, err := h.Create(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = created.PhysicalID
			r.Previous = original
			r.Properties = cloudformation.Properties{"Description": "real native parameter owner", "CacheParameterGroupFamily": "valkey8", "Properties": map[string]any{"tcp-keepalive": "100"}}
			if _, err = h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			p, err := h.Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			identifier, err := cloudformation.ResourceIdentifier("AWS::ElastiCache::ParameterGroup", p)
			if err != nil || identifier != r.PhysicalID {
				t.Fatalf("owner observations cannot be addressed through Cloud Control: %q, %v", identifier, err)
			}
			values, ok := p["Properties"].(map[string]string)
			if !ok || len(values) != 1 || values["tcp-keepalive"] != "100" {
				t.Fatalf("removed parameter remained configured in authoritative owner: %#v", p["Properties"])
			}
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"Description": "real native parameter owner", "CacheParameterGroupFamily": "valkey8", "Properties": map[string]any{"timeout": "-1"}}
			if _, err = h.Update(ctx, r); err == nil {
				t.Fatal("invalid native parameter value was admitted")
			}
			p, err = h.Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			values, ok = p["Properties"].(map[string]string)
			if !ok || len(values) != 1 || values["tcp-keepalive"] != "100" {
				t.Fatalf("rejected replacement cleared previously effective parameters: %#v", p["Properties"])
			}
			r.Previous = cloudformation.Properties{"Description": "real native parameter owner", "CacheParameterGroupFamily": "valkey8", "Properties": map[string]any{"tcp-keepalive": "100"}}
			r.Properties = cloudformation.Properties{"Description": "real native parameter owner", "CacheParameterGroupFamily": "valkey8", "Properties": map[string]any{}}
			if _, err = h.Update(ctx, r); err != nil {
				t.Fatal(err)
			}
			p, err = h.Read(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			values, ok = p["Properties"].(map[string]string)
			if !ok || len(values) != 0 {
				t.Fatalf("empty desired parameter map did not restore native defaults: %#v", p["Properties"])
			}
			if err = h.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNCacheGeneratedNamesPreserveNativeIdentifiers(t *testing.T) {
	ctx := cfnWorkflowOwnerContext(t)
	service := owner.New(owner.Config{})
	t.Cleanup(func() { _ = service.Close() })
	h := cfnCacheParameterGroup{commands: NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"elasticache": service})}
	cases := []struct{ stack, logical string }{
		{"", "Parameters"},
		{"", ""},
		{"123", "Parameters"},
		{"cache--stack", "--Parameters"},
		{strings.Repeat("a", 24) + "-long", "Parameters"},
	}
	for i, tc := range cases {
		t.Run(tc.stack+"/"+tc.logical, func(t *testing.T) {
			r := cfnWorkflowOwnerRequest("AWS::ElastiCache::ParameterGroup", tc.logical, cloudformation.Properties{"Description": "native naming admission", "CacheParameterGroupFamily": "valkey8"})
			r.StackName = tc.stack
			for _, limit := range []int{40, 50} {
				name := cfnEngineName(r, "CacheParameterGroupName", limit)
				if len(name) > limit || !strings.HasSuffix(name, "-"+cfnComputeHash(r.StackID+"/"+r.LogicalID+"/"+r.Token)) {
					t.Fatalf("generated identifier lost its bound or incarnation hash: %q", name)
				}
			}
			created, err := h.Create(ctx, r)
			if err != nil {
				t.Fatalf("generated identifier failed native admission for case %d: %v", i, err)
			}
			replayed, err := h.Create(ctx, r)
			if err != nil || replayed.PhysicalID != created.PhysicalID {
				t.Fatalf("generated identifier changed on replay: %+v %v", replayed, err)
			}
			r.PhysicalID = created.PhysicalID
			if err := h.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
	invalid := cfnWorkflowOwnerRequest("AWS::ElastiCache::ParameterGroup", "Invalid", cloudformation.Properties{"Description": "native naming admission", "CacheParameterGroupFamily": "valkey8"})
	invalid.PhysicalID = "-invalid"
	if created, err := h.Create(ctx, invalid); err == nil || created.PhysicalID != "" {
		t.Fatalf("invalid supplied identifier bypassed native validation: %+v %v", created, err)
	}
}
