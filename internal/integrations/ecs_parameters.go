package integrations

import (
	"context"
	"encoding/json"
	"fmt"

	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ecs"
)

// ECSParameters resolves task secrets with execution-role credentials, never the
// deploying identity or task role. Full ARNs select the secret's region.
type ECSParameters struct {
	Parameters ParameterStoreAPI
	Secrets    ECSSecretsAPI
}

type ECSSecretsAPI interface {
	GetSecretValue(context.Context, *api.GetSecretValueInput) (*api.GetSecretValueOutput, *awswire.Error)
}

var _ ecs.TaskParameters = ECSParameters{}

func (a ECSParameters) Read(ctx context.Context, key ecs.TaskKey, references []string, credentials ecs.TaskCredentialSource) (map[string]string, error) {
	if credentials == nil {
		return nil, fmt.Errorf("task secrets require execution-role credentials")
	}
	credential, rejected := credentials(ctx)
	if rejected != nil {
		return nil, rejected
	}
	if credential.AccountID != key.AccountID {
		return nil, fmt.Errorf("execution-role credential account differs from task %s", key.ARN())
	}
	command, rejected := serviceRoleRequestContext(ctx, credential, key.Region, "ecs-tasks.amazonaws.com")
	if rejected != nil {
		return nil, rejected
	}
	values := make(map[string]string, len(references))
	var parameters []string
	for _, reference := range references {
		resource, err := arn.Parse(reference)
		if err != nil || resource.Service != "secretsmanager" {
			parameters = append(parameters, reference)
			continue
		}
		content, err := a.readSecret(command, reference, resource)
		if err != nil {
			return nil, err
		}
		values[reference] = content
	}
	if len(parameters) != 0 {
		if a.Parameters == nil {
			return nil, fmt.Errorf("SSM task parameter adapter is unavailable")
		}
		resolved, err := readParameterValues(command, a.Parameters, parameters, true)
		if err != nil {
			return nil, err
		}
		for reference, content := range resolved {
			values[reference] = content
		}
	}
	return values, nil
}

// Match the existing CodeBuild selector and string-JSON-value rules without
// borrowing its build identity or command context.
func (a ECSParameters) readSecret(ctx context.Context, reference string, resource arn.ARN) (string, error) {
	parts := strings.Split(reference, ":")
	if len(parts) < 7 || len(parts) > 10 || parts[5] != "secret" || parts[6] == "" || resource.Region == "" || resource.AccountID == "" {
		return "", fmt.Errorf("invalid ECS Secrets Manager ARN")
	}
	if a.Secrets == nil {
		return "", fmt.Errorf("task Secrets Manager adapter is unavailable")
	}
	input := &api.GetSecretValueInput{SecretId: new(api.SecretIdType(strings.Join(parts[:7], ":")))}
	key := ""
	if len(parts) > 7 {
		key = parts[7]
	}
	if len(parts) > 8 && parts[8] != "" {
		input.VersionStage = new(api.SecretVersionStageType(parts[8]))
	}
	if len(parts) > 9 && parts[9] != "" {
		input.VersionId = new(api.SecretVersionIdType(parts[9]))
	}
	if input.VersionStage != nil && input.VersionId != nil {
		return "", fmt.Errorf("ECS secret version stage and version ID are mutually exclusive")
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Region = resource.Region
	out, rejected := a.Secrets.GetSecretValue(awsctx.WithMetadata(ctx, metadata), input)
	if rejected != nil {
		return "", rejected
	}
	if out.SecretString == nil {
		return "", fmt.Errorf("ECS container secrets require SecretString; binary secrets are unsupported")
	}
	content := string(*out.SecretString)
	if key == "" {
		return content, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &fields); err != nil {
		return "", fmt.Errorf("ECS secret is not a JSON object")
	}
	raw, found := fields[key]
	var selected string
	if !found || string(raw) == "null" || json.Unmarshal(raw, &selected) != nil {
		return "", fmt.Errorf("ECS secret JSON key is absent or not a string")
	}
	return selected, nil
}
