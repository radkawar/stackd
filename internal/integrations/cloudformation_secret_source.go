package integrations

import (
	"context"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationSecretSource preserves the native owner's GetSecretValue and
// KMS decrypt authorization for every resolution, including pinned retries.
type CloudFormationSecretSource struct{ Commands StepFunctionsCommands }

func (a CloudFormationSecretSource) ResolveSecretVersion(ctx context.Context, selector cloudformation.SecretVersionSelector) (string, string, error) {
	input := map[string]any{"SecretId": selector.SecretID}
	if selector.VersionID != "" {
		input["VersionId"] = selector.VersionID
	}
	if selector.VersionStage != "" {
		input["VersionStage"] = selector.VersionStage
	}
	out, err := cfnComputeCall[api.GetSecretValueOutput](ctx, a.Commands, "secretsmanager", "GetSecretValue", input)
	if err != nil {
		return "", "", err
	}
	if out.SecretString == nil {
		return "", "", &awswire.Error{Code: "ValidationError", Message: "Secrets Manager dynamic references require SecretString, not SecretBinary.", StatusCode: 400}
	}
	return cfnComputeValue(out.SecretString), cfnComputeValue(out.VersionId), nil
}
