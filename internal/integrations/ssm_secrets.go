package integrations

import (
	"context"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ssm"
)

type SSMSecretCommands interface {
	GetSecretValue(context.Context, *api.GetSecretValueInput) (*api.GetSecretValueOutput, *awswire.Error)
}

type SSMSecrets struct{ Secrets SSMSecretCommands }

func (a SSMSecrets) GetParameterSecret(ctx context.Context, reference ssm.SecretReference) (ssm.ReferencedSecret, error) {
	input := &api.GetSecretValueInput{SecretId: new(api.SecretIdType(reference.ID))}
	if reference.VersionID != "" {
		input.VersionId = new(api.SecretVersionIdType(reference.VersionID))
	}
	if reference.VersionStage != "" {
		input.VersionStage = new(api.SecretVersionStageType(reference.VersionStage))
	}
	m := awsctx.FromContext(ctx)
	m.RequestID, m.ParentEventID = uuid.NewString(), apievents.EventID(ctx)
	m.InvokedBy = "ssm.amazonaws.com"
	ctx = awsctx.WithViaService(awsctx.WithMetadata(ctx, m), "ssm.amazonaws.com")
	out, rejected := a.Secrets.GetSecretValue(ctx, input)
	if rejected != nil {
		return ssm.ReferencedSecret{}, rejected
	}
	result := ssm.ReferencedSecret{Value: (*string)(out.SecretString), Binary: out.SecretBinary, VersionStages: make([]string, len(out.VersionStages))}
	for i, stage := range out.VersionStages {
		result.VersionStages[i] = string(stage)
	}
	if out.ARN != nil {
		result.ARN = string(*out.ARN)
	}
	if out.CreatedDate != nil {
		result.Modified = *out.CreatedDate
	}
	if out.Name != nil {
		result.Name = string(*out.Name)
	}
	if out.VersionId != nil {
		result.VersionID = string(*out.VersionId)
	}
	return result, nil
}
