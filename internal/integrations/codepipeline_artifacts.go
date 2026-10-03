package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/codepipeline"
)

// CodePipelineArtifacts resolves retained producer metadata, never artifact bytes.
// The consumers still enter S3 under their current execution/caller authority.
type CodePipelineArtifacts struct{ Repository codepipeline.Repository }

func (a CodePipelineArtifacts) ResolveDeployment(ctx context.Context, scope codepipeline.Scope, pipeline, actionID string) (codepipeline.ActionRequest, bool, error) {
	return codepipeline.ResolveDeployment(ctx, a.Repository, scope, pipeline, actionID)
}

func (a CodePipelineArtifacts) ResolveBuild(ctx context.Context, actionID, projectARN, sourceARN, outputARN string) (codebuild.PipelineBuild, error) {
	m := awsctx.FromContext(ctx)
	scope := codepipeline.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
	action, found, err := codepipeline.ResolveAction(ctx, a.Repository, scope, actionID)
	if err != nil {
		return codebuild.PipelineBuild{}, err
	}
	if !found {
		return codebuild.PipelineBuild{}, fmt.Errorf("CodePipeline action %s is no longer available", actionID)
	}
	configuration := action.Action.Configuration
	expectedProject := "arn:" + scope.Partition + ":codebuild:" + scope.Region + ":" + scope.AccountID + ":project/" + string(configuration["ProjectName"])
	if projectARN != expectedProject {
		return codebuild.PipelineBuild{}, fmt.Errorf("CodePipeline action does not bind project %s", projectARN)
	}
	primary, err := pipelinePrimaryArtifact(action)
	if err != nil {
		return codebuild.PipelineBuild{}, err
	}
	result := codebuild.PipelineBuild{PipelineName: action.PipelineName, Inputs: make([]codebuild.PipelineInput, 0, len(action.InputArtifacts)), Outputs: make([]codebuild.PipelineOutput, 0, len(action.OutputArtifacts))}
	if pipelineArtifactARN(scope.Partition, primary) != sourceARN {
		return result, fmt.Errorf("CodePipeline primary source does not match the admitted artifact")
	}
	result.Inputs = append(result.Inputs, pipelineBuildInput(scope.Partition, primary))
	for _, artifact := range action.InputArtifacts {
		if artifact.Name != primary.Name {
			result.Inputs = append(result.Inputs, pipelineBuildInput(scope.Partition, artifact))
		}
	}
	expectedOutput := ""
	for _, artifact := range action.OutputArtifacts {
		location := pipelineArtifactARN(scope.Partition, artifact)
		if expectedOutput == "" {
			expectedOutput = location
		}
		result.Outputs = append(result.Outputs, codebuild.PipelineOutput{Name: artifact.Name, Location: location, EncryptionKey: pipelineArtifactKey(action.ArtifactStore)})
	}
	if outputARN != expectedOutput {
		return result, fmt.Errorf("CodePipeline output does not match the admitted artifact")
	}
	return result, nil
}

func pipelinePrimaryArtifact(action codepipeline.ActionRequest) (codepipeline.Artifact, error) {
	primary := string(action.Action.Configuration["PrimarySource"])
	if primary == "" && len(action.InputArtifacts) == 1 {
		return action.InputArtifacts[0], nil
	}
	for _, artifact := range action.InputArtifacts {
		if artifact.Name == primary {
			return artifact, nil
		}
	}
	return codepipeline.Artifact{}, fmt.Errorf("CodePipeline primary source %q is not bound", primary)
}

func pipelineBuildInput(partition string, artifact codepipeline.Artifact) codebuild.PipelineInput {
	return codebuild.PipelineInput{Name: artifact.Name, Location: pipelineArtifactARN(partition, artifact), VersionID: artifact.VersionID, RevisionID: artifact.RevisionID}
}
func pipelineArtifactARN(partition string, artifact codepipeline.Artifact) string {
	return "arn:" + partition + ":s3:::" + artifact.Bucket + "/" + artifact.Key
}
func pipelineArtifactKey(store api.ArtifactStore) string {
	if store.EncryptionKey != nil && store.EncryptionKey.Id != nil {
		return string(*store.EncryptionKey.Id)
	}
	return "alias/aws/s3"
}
