package ecr

import (
	"context"
	"errors"
	"net/http/httptest"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"testing"
)

func ownershipCommand(ctx context.Context, service *Service, name string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("ecr")
	op, _ := model.Operation(name)
	return service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
}

func TestCloudFormationRegistryReleaseRecoveryAndRecreationFence(t *testing.T) {
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository})
	t.Cleanup(func() { service.Close() })
	scope := Scope{"aws", "123456789012", "us-east-1"}
	ctx := lifecycleTestContext(scope)
	input := &api.PutReplicationConfigurationInput{ReplicationConfiguration: &api.ReplicationConfiguration{Rules: api.ReplicationRuleList{}}}
	create := WithCloudFormationOwnership(ctx, "ReplicationConfiguration", "first", false, false, nil)
	if _, rejected := ownershipCommand(create, service, "PutReplicationConfiguration", input); rejected != nil {
		t.Fatal(rejected)
	}
	// Direct owner commands retain internal claims while replacing configuration.
	if _, rejected := ownershipCommand(ctx, service, "PutReplicationConfiguration", input); rejected != nil {
		t.Fatal(rejected)
	}
	if err := repository.View(ctx, func(reader Reader) error {
		r, err := reader.Registry(scope)
		if err != nil {
			return err
		}
		if r.ReplicationOwnership != "first" {
			t.Fatal("ordinary write lost incarnation metadata")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deletion := WithCloudFormationOwnership(ctx, "ReplicationConfiguration", "first", true, true, nil)
	for range 2 {
		if _, rejected := ownershipCommand(deletion, service, "PutReplicationConfiguration", input); rejected != nil {
			t.Fatal(rejected)
		}
	}
	second := WithCloudFormationOwnership(ctx, "ReplicationConfiguration", "second", false, false, nil)
	if _, rejected := ownershipCommand(second, service, "PutReplicationConfiguration", input); rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected := ownershipCommand(deletion, service, "PutReplicationConfiguration", input); rejected == nil {
		t.Fatal("stale rollback cleared a recreated registry configuration")
	}
	if err := repository.View(ctx, func(reader Reader) error {
		r, err := reader.Registry(scope)
		if err != nil {
			return err
		}
		if r.ReplicationOwnership != "second" {
			t.Fatal("stale rollback changed incarnation metadata")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCloudFormationRepositoryClaimIgnoresForgedTagsAndFencesRecreation(t *testing.T) {
	repository := NewMemoryRepository(nil)
	registry := httptest.NewUnstartedServer(nil)
	service := New(Config{Repository: repository, PublicEndpoint: "http://" + registry.Listener.Addr().String()})
	registry.Config.Handler = service.RegistryHandler()
	registry.Start()
	t.Cleanup(registry.Close)
	t.Cleanup(func() { service.Close() })
	scope := Scope{"aws", "123456789012", "us-east-1"}
	ctx := lifecycleTestContext(scope)
	key := RepositoryKey{scope, "owned"}
	arn := repositoryARN(key)
	name := new(api.RepositoryName("owned"))
	const claim = `["stack","Repository","first"]`
	// Exact copies of the legacy public markers carry no authority.
	forged := api.TagList{
		{Key: new(api.TagKey("stackd:cloudformation:stack-id")), Value: new(api.TagValue("stack"))},
		{Key: new(api.TagKey("stackd:cloudformation:logical-id")), Value: new(api.TagValue("Repository"))},
		{Key: new(api.TagKey("stackd:cloudformation:incarnation")), Value: new(api.TagValue("first"))},
	}
	ownership := func() string {
		t.Helper()
		var v string
		if err := repository.View(ctx, func(r Reader) error {
			repo, err := r.Repository(key)
			if errors.Is(err, ErrNotFound) {
				v = "<missing>"
				return nil
			}
			v = repo.Ownership
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return v
	}
	admit := WithCloudFormationOwnership(ctx, RepositoryOwnershipKind, claim, false, false, nil)
	owner := WithCloudFormationOwnership(ctx, RepositoryOwnershipKind, claim, true, false, nil)
	if _, rejected := ownershipCommand(admit, service, "CreateRepository", &api.CreateRepositoryInput{RepositoryName: name}); rejected != nil {
		t.Fatal(rejected)
	}
	if got := ownership(); got != claim {
		t.Fatalf("bound creation did not stamp the private claim: %q", got)
	}
	if _, rejected := ownershipCommand(ctx, service, "TagResource", &api.TagResourceInput{ResourceArn: new(api.Arn(arn)), Tags: forged}); rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected := ownershipCommand(owner, service, "PutImageTagMutability", &api.PutImageTagMutabilityInput{RepositoryName: name, ImageTagMutability: new(api.ImageTagMutability("IMMUTABLE"))}); rejected != nil {
		t.Fatal(rejected)
	}
	if got := ownership(); got != claim {
		t.Fatalf("ordinary writes changed the private claim: %q", got)
	}
	observed := map[string]string{}
	describe := &api.DescribeRepositoriesInput{RepositoryNames: api.RepositoryNameList{"owned"}}
	if _, rejected := ownershipCommand(WithCloudFormationOwnership(ctx, RepositoryOwnershipKind, claim, false, false, observed), service, "DescribeRepositories", describe); rejected != nil || observed[arn] != claim {
		t.Fatalf("authorized exact describe did not observe the claim: %v %v", observed, rejected)
	}
	// Native delete and same-name recreation with copied markers stays unclaimed.
	if _, rejected := ownershipCommand(ctx, service, "DeleteRepository", &api.DeleteRepositoryInput{RepositoryName: name}); rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected := ownershipCommand(ctx, service, "CreateRepository", &api.CreateRepositoryInput{RepositoryName: name, Tags: forged}); rejected != nil {
		t.Fatal(rejected)
	}
	if got := ownership(); got != "" {
		t.Fatalf("native recreation acquired a claim from public tags: %q", got)
	}
	for op, input := range map[string]any{
		"DescribeRepositories":  describe,
		"PutImageTagMutability": &api.PutImageTagMutabilityInput{RepositoryName: name, ImageTagMutability: new(api.ImageTagMutability("MUTABLE"))},
		"TagResource":           &api.TagResourceInput{ResourceArn: new(api.Arn(arn)), Tags: api.TagList{{Key: new(api.TagKey("k")), Value: new(api.TagValue("v"))}}},
		"DeleteRepository":      &api.DeleteRepositoryInput{RepositoryName: name, Force: new(api.ForceFlag(true))},
	} {
		if _, rejected := ownershipCommand(owner, service, op, input); rejected == nil {
			t.Fatalf("stale owner %s reached a native recreation", op)
		}
	}
	if _, rejected := ownershipCommand(admit, service, "CreateRepository", &api.CreateRepositoryInput{RepositoryName: name}); rejected == nil {
		t.Fatal("owner creation adopted a native repository")
	}
	if got := ownership(); got != "" {
		t.Fatalf("rejected owner calls changed the native recreation: %q", got)
	}
	observed = map[string]string{}
	if _, rejected := ownershipCommand(WithCloudFormationOwnership(ctx, RepositoryOwnershipKind, claim, false, false, observed), service, "DescribeRepositories", describe); rejected != nil || observed[arn] != "" {
		t.Fatalf("native recreation observed as owned: %v %v", observed, rejected)
	}
}
