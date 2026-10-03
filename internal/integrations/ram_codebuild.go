package integrations

import (
	"context"

	"stackd/internal/authorization"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/ram"
)

// CodeBuildRAM is the RAM authority consumed by the CodeBuild adapter.
type CodeBuildRAM interface {
	ResourcePolicies(context.Context, string) ([]authorization.BoundPolicy, error)
	SharedResources(context.Context, ram.SharedResourcesQuery) ([]ram.ResourceIdentity, error)
	HasResourceShares(context.Context, string) (bool, error)
	ResourceDeleted(context.Context, string) error
}

// CodeBuildResourceShares resolves live RAM policies and discovery using the
// CodeBuild repository's transaction context. No grant cache is retained.
type CodeBuildResourceShares struct{ RAM CodeBuildRAM }

func (a CodeBuildResourceShares) ResourcePolicies(ctx context.Context, resource string) ([]authorization.BoundPolicy, error) {
	return a.RAM.ResourcePolicies(ctx, resource)
}

func (a CodeBuildResourceShares) HasResourceShares(ctx context.Context, resource string) (bool, error) {
	return a.RAM.HasResourceShares(ctx, resource)
}

func (a CodeBuildResourceShares) ResourceDeleted(ctx context.Context, resource string) error {
	return a.RAM.ResourceDeleted(ctx, resource)
}

func (a CodeBuildResourceShares) SharedProjects(ctx context.Context, scope codebuild.Scope) ([]codebuild.SharedProject, error) {
	resources, err := a.RAM.SharedResources(ctx, ram.SharedResourcesQuery{
		Partition: scope.Partition, Region: scope.Region, AccountID: scope.AccountID,
		ResourceType: "codebuild:Project", Action: "codebuild:BatchGetProjects",
	})
	if err != nil {
		return nil, err
	}
	out := make([]codebuild.SharedProject, 0, len(resources))
	for _, resource := range resources {
		out = append(out, codebuild.SharedProject{
			Scope: codebuild.Scope{Partition: resource.Partition, AccountID: resource.AccountID, Region: resource.Region},
			ARN:   resource.ARN,
		})
	}
	return out, nil
}

var _ codebuild.ResourceShares = CodeBuildResourceShares{}
