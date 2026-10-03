package secretsmanager

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/secretsmanager"
	"stackd/internal/awswire"
)

type managedOwnerKey struct{}

func managedOwner(ctx context.Context) string {
	owner, _ := ctx.Value(managedOwnerKey{}).(string)
	return owner
}
func validSecretName(ctx context.Context, name string) bool {
	owner := managedOwner(ctx)
	if owner != "" {
		prefix := owner + "!"
		return strings.HasPrefix(name, prefix) && secretNamePattern.MatchString(strings.TrimPrefix(name, prefix))
	}
	return secretNamePattern.MatchString(name)
}

// CreateManaged is a trusted service integration, not an HTTP authorization
// bypass. The supplied service principal/role still needs normal secret and KMS
// permissions. Its namespace and immutable owning-service tag stay source-owned.
func (s *Service) CreateManaged(ctx context.Context, owner string, in *api.CreateSecretInput) (*api.CreateSecretOutput, *awswire.Error) {
	if owner == "" {
		return nil, failure("InvalidParameterException", "A managed secret requires an owning service.")
	}
	return runCommand(s, context.WithValue(ctx, managedOwnerKey{}, owner), "CreateSecret", in, s.createSecret)
}
func (s *Service) UpdateManaged(ctx context.Context, owner string, in *api.UpdateSecretInput) (*api.UpdateSecretOutput, *awswire.Error) {
	if owner == "" {
		return nil, failure("InvalidParameterException", "A managed secret requires an owning service.")
	}
	return runCommand(s, context.WithValue(ctx, managedOwnerKey{}, owner), "UpdateSecret", in, s.updateSecret)
}
func (s *Service) DeleteManaged(ctx context.Context, owner string, in *api.DeleteSecretInput) (*api.DeleteSecretOutput, *awswire.Error) {
	if owner == "" {
		return nil, failure("InvalidParameterException", "A managed secret requires an owning service.")
	}
	return runCommand(s, context.WithValue(ctx, managedOwnerKey{}, owner), "DeleteSecret", in, s.deleteSecret)
}

// DescribeSecret and GetSecretValue are the same authorized, audited commands
// used by the generated frontend. Internal consumers cannot bypass either check.
func (s *Service) DescribeSecret(ctx context.Context, in *api.DescribeSecretInput) (*api.DescribeSecretOutput, *awswire.Error) {
	return runCommand(s, ctx, "DescribeSecret", in, s.describeSecret)
}
func (s *Service) GetSecretValue(ctx context.Context, in *api.GetSecretValueInput) (*api.GetSecretValueOutput, *awswire.Error) {
	return runCommand(s, ctx, "GetSecretValue", in, s.getSecretValue)
}

// Resource policy consumers use the same current-authority command boundary as
// the generated frontend; integrations cannot mutate a policy through storage.
func (s *Service) GetResourcePolicy(ctx context.Context, in *api.GetResourcePolicyInput) (*api.GetResourcePolicyOutput, *awswire.Error) {
	return runCommand(s, ctx, "GetResourcePolicy", in, s.getResourcePolicy)
}
func (s *Service) PutResourcePolicy(ctx context.Context, in *api.PutResourcePolicyInput) (*api.PutResourcePolicyOutput, *awswire.Error) {
	return runCommand(s, ctx, "PutResourcePolicy", in, s.putResourcePolicy)
}
func (s *Service) DeleteResourcePolicy(ctx context.Context, in *api.DeleteResourcePolicyInput) (*api.DeleteResourcePolicyOutput, *awswire.Error) {
	return runCommand(s, ctx, "DeleteResourcePolicy", in, s.deleteResourcePolicy)
}
