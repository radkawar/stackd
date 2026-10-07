package integrations

import (
	"context"
	"encoding/json"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/codepipeline"
)

func cfnDeveloperCodeBuildContext(ctx context.Context, r cloudformation.ResourceRequest, kind string) context.Context {
	if r.CloudControl {
		return ctx
	}
	return codebuild.WithCloudFormationResourceOwnership(ctx, kind, cfnDeveloperClaim(r), r.PhysicalID, true, nil)
}
func cfnDeveloperPipelineContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return codepipeline.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), r.PhysicalID, true, nil)
}
func cfnDeveloperPipelineUpdateHash(r cloudformation.ResourceRequest) string {
	raw, _ := json.Marshal([]any{r.Token, r.Previous, r.Properties})
	return cfnComputeHash(string(raw))
}
func cfnDeveloperPipelineUpdateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return codepipeline.WithCloudFormationUpdate(cfnDeveloperPipelineContext(ctx, r), cfnDeveloperPipelineUpdateHash(r))
}
