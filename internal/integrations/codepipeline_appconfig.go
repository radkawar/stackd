package integrations

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/awswire"
	"stackd/internal/services/appconfig"
	"stackd/internal/services/codepipeline"
)

func (a *CodePipelineActions) deploy(ctx context.Context, request codepipeline.ActionRequest) (codepipeline.ActionResult, error) {
	var deployment *api.Deployment
	if request.ExternalExecutionID == "" {
		configuration := request.Action.Configuration
		input := &api.StartDeploymentInput{ApplicationId: new(api.Name(configuration["Application"])), EnvironmentId: new(api.Name(configuration["Environment"])), ConfigurationProfileId: new(api.LongName(configuration["ConfigurationProfile"])), ConfigurationVersion: new(api.Version(request.ActionExecutionID)), DeploymentStrategyId: new(api.DeploymentStrategyId(configuration["DeploymentStrategy"]))}
		raw, err := pipelineCommand(appconfig.WithPipelineAction(ctx, request.ActionExecutionID), a.AppConfig, "appconfig", "StartDeployment", input)
		if err != nil {
			if rejected, ok := err.(*awswire.Error); ok && rejected.StatusCode == 403 {
				return codepipeline.ActionResult{Status: "Failed", ErrorCode: "PermissionError", Summary: fmt.Sprintf("Permissions error trying to access application %s, environment %s, configuration profile %s, with version %s.", configuration["Application"], configuration["Environment"], configuration["ConfigurationProfile"], request.ActionExecutionID)}, nil
			}
			return codepipeline.ActionResult{}, err
		}
		deployment = raw.(*api.StartDeploymentOutput)
	} else {
		parts := strings.Split(request.ExternalExecutionID, "/")
		if len(parts) != 6 {
			return codepipeline.ActionResult{}, fmt.Errorf("invalid retained AppConfig deployment handle %q", request.ExternalExecutionID)
		}
		number, err := strconv.ParseInt(parts[5], 10, 32)
		if err != nil {
			return codepipeline.ActionResult{}, fmt.Errorf("invalid AppConfig deployment number: %w", err)
		}
		raw, err := pipelineCommand(ctx, a.AppConfig, "appconfig", "GetDeployment", &api.GetDeploymentInput{ApplicationId: new(api.Name(parts[1])), EnvironmentId: new(api.Name(parts[3])), DeploymentNumber: new(api.Integer(number))})
		if err != nil {
			return codepipeline.ActionResult{}, err
		}
		deployment = raw.(*api.GetDeploymentOutput)
	}
	handle := "applications/" + pipelineString(deployment.ApplicationId) + "/environments/" + pipelineString(deployment.EnvironmentId) + "/deployments/" + strconv.FormatInt(int64(*deployment.DeploymentNumber), 10)
	result := codepipeline.ActionResult{ExternalExecutionID: handle, ExternalExecutionURL: "https://console.aws.amazon.com/systems-manager/appconfig/" + handle + "/details?region=" + request.Region}
	switch state := pipelineString(deployment.State); state {
	case "VALIDATING", "DEPLOYING", "BAKING", "ROLLING_BACK":
		result.Status = "InProgress"
	case "COMPLETE":
		result.Status, result.Summary = "Succeeded", "Deployment succeeded!"
	case "ROLLED_BACK", "REVERTED":
		result.Status, result.ErrorCode = "Failed", "JobFailed"
		result.ErrorMessage = "AppConfig deployment ended in state " + state
		if len(deployment.EventLog) != 0 && deployment.EventLog[0].Description != nil {
			result.ErrorMessage += ": " + string(*deployment.EventLog[0].Description)
		}
	default:
		return result, fmt.Errorf("AppConfig returned unknown deployment state %q", state)
	}
	return result, nil
}
