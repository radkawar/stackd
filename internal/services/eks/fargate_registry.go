package eks

import (
	"context"
	"errors"
	native "stackd/compute/eks"
)

// FargateRegistries supplies current role-bound pull credentials for exact real
// workload images. Native agents consume them privately, outside the state tx.
type FargateRegistries interface {
	FargateImageAuthorization(context.Context, string, string, string, []string) ([]native.RegistryAuthorization, error)
}

func (s *Service) fargateRegistryAuthorization(p FargateProfile) func(context.Context, []string) ([]native.RegistryAuthorization, error) {
	return func(ctx context.Context, images []string) ([]native.RegistryAuthorization, error) {
		registry, ok := s.workloadRoles.(FargateRegistries)
		if !ok {
			return nil, errors.New("fargate registry execution authority is unavailable")
		}
		return registry.FargateImageAuthorization(ctx, p.RoleARN, p.RoleID, p.ARN(), images)
	}
}
