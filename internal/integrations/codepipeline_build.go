package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	buildapi "stackd/internal/awsapi/codebuild"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/codepipeline"
)

func (a *CodePipelineActions) build(ctx context.Context, request codepipeline.ActionRequest) (codepipeline.ActionResult, error) {
	var build *buildapi.Build
	if request.ExternalExecutionID == "" {
		primary, err := pipelinePrimaryArtifact(request)
		if err != nil {
			return codepipeline.ActionResult{}, err
		}
		project := string(request.Action.Configuration["ProjectName"])
		input := &buildapi.StartBuildInput{ProjectName: new(buildapi.NonEmptyString(project)), SourceVersion: new(buildapi.String(pipelineArtifactARN(request.Partition, primary))), IdempotencyToken: new(buildapi.String(request.ActionExecutionID))}
		if len(request.OutputArtifacts) != 0 {
			input.ArtifactsOverride = &buildapi.ProjectArtifacts{Type: new(buildapi.ArtifactsType("CODEPIPELINE")), Location: new(buildapi.String(pipelineArtifactARN(request.Partition, request.OutputArtifacts[0]))), Name: new(buildapi.String(project)), Packaging: new(buildapi.ArtifactPackaging("NONE")), EncryptionDisabled: new(buildapi.WrapperBoolean(false))}
		} else {
			input.ArtifactsOverride = &buildapi.ProjectArtifacts{Type: new(buildapi.ArtifactsType("NO_ARTIFACTS"))}
		}
		if variables := string(request.Action.Configuration["EnvironmentVariables"]); variables != "" {
			if err := json.Unmarshal([]byte(variables), &input.EnvironmentVariablesOverride); err != nil {
				return codepipeline.ActionResult{}, fmt.Errorf("invalid CodeBuild action EnvironmentVariables: %w", err)
			}
		}
		raw, err := pipelineCommand(codebuild.WithPipelineAction(ctx, request.ActionExecutionID), a.CodeBuild, "codebuild", "StartBuild", input)
		if err != nil {
			return codepipeline.ActionResult{Status: "Failed", ErrorCode: "JobFailed", Summary: "Error calling startBuild: " + err.Error()}, nil
		}
		build = raw.(*buildapi.StartBuildOutput).Build
	} else {
		raw, err := pipelineCommand(ctx, a.CodeBuild, "codebuild", "BatchGetBuilds", &buildapi.BatchGetBuildsInput{Ids: buildapi.BuildIds{buildapi.NonEmptyString(request.ExternalExecutionID)}})
		if err != nil {
			return codepipeline.ActionResult{}, err
		}
		rows := raw.(*buildapi.BatchGetBuildsOutput).Builds
		if len(rows) == 0 {
			return codepipeline.ActionResult{}, fmt.Errorf("CodeBuild execution %s no longer exists", request.ExternalExecutionID)
		}
		build = &rows[0]
	}
	id := pipelineString(build.Id)
	result := codepipeline.ActionResult{ExternalExecutionID: id, ExternalExecutionURL: "https://console.aws.amazon.com/codebuild/home?region=" + request.Region + "#/builds/" + id + "/view/new"}
	switch status := pipelineString(build.BuildStatus); status {
	case "IN_PROGRESS":
		result.Status = "InProgress"
	case "SUCCEEDED":
		result.Status = "Succeeded"
		result.Artifacts = slices.Clone(request.OutputArtifacts)
		for i := range result.Artifacts {
			result.Artifacts[i].RevisionID = pipelineString(build.ResolvedSourceVersion)
		}
		result.OutputVariables = make(api.OutputVariablesMap, len(build.ExportedEnvironmentVariables))
		for _, variable := range build.ExportedEnvironmentVariables {
			result.OutputVariables[api.OutputVariablesKey(pipelineString(variable.Name))] = api.OutputVariablesValue(pipelineString(variable.Value))
		}
	case "FAILED", "FAULT", "TIMED_OUT", "STOPPED":
		result.Status, result.ErrorCode = "Failed", "JobFailed"
		result.ErrorMessage = "Build terminated with state: " + status
		for _, phase := range build.Phases {
			for _, diagnostic := range phase.Contexts {
				if message := pipelineString(diagnostic.Message); message != "" {
					result.ErrorMessage += ". Phase: " + pipelineString(phase.PhaseType) + ", Code: " + pipelineString(diagnostic.StatusCode) + ", Message: " + message
				}
			}
		}
	default:
		return result, fmt.Errorf("CodeBuild returned unknown execution status %q", status)
	}
	return result, nil
}
