package integrations

import (
	"context"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/secretsmanager"
)

func cfnSecretOwnerContext(ctx context.Context, r cloudformation.ResourceRequest, aspect string, create, remove bool) context.Context {
	if aspect == "attachment" {
		ctx = secretsmanager.WithSecretTargetAttachment(ctx, remove)
	}
	if r.CloudControl && !create {
		return ctx
	}
	return secretsmanager.WithCloudFormationOwnership(ctx, secretsmanager.CloudFormationOwnership{Owner: cfnMessagingOwner(r), Token: cfnMessagingHash(r.Token)}, aspect, create, remove)
}
func cfnSecretRecovery(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, aspect, id string) (cloudformation.ResourceResult, error) {
	ctx = cfnSecretOwnerContext(ctx, r, aspect, true, false)
	out, _, err := cfnSecretDescribe(ctx, c, id)
	if secretsmanager.IsCloudFormationOwnershipMismatch(err) {
		return cloudformation.ResourceResult{}, &awswire.Error{Code: "ResourceNotFoundException", Message: "This secret resource or edge incarnation has not been admitted.", StatusCode: 404}
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnSecretResult(cfnComputeValue(out.ARN)), nil
}
func (h cfnSecret) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnSecretRecovery(ctx, h.commands, r, "secret", cfnComputeName(r, "Name", 256))
}
func (h cfnSecretPolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnSecretRecovery(ctx, h.commands, r, "policy", cfnComputeString(r.Properties, "SecretId"))
}
func (h cfnSecretRotation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnSecretRecovery(ctx, h.commands, r, "rotation", cfnComputeString(r.Properties, "SecretId"))
}
func (h cfnSecretAttachment) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return cfnSecretRecovery(ctx, h.commands, r, "attachment", cfnComputeString(r.Properties, "SecretId"))
}
