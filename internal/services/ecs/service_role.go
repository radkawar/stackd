package ecs

import (
	"context"
	"errors"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const ServicePrincipal = "ecs.amazonaws.com"

// ServiceRoles owns linked-role creation and its IAM permission check. Permission
// denial must leave a joined resource transaction usable, without creating a role.
type ServiceRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

func (s *Service) ensureClusterRole(ctx context.Context) error {
	if s.roles == nil {
		return unsupported("Cluster creation requires an IAM service-role provider.")
	}
	ctx = awsctx.WithViaService(ctx, ServicePrincipal)
	metadata := awsctx.FromContext(ctx)
	metadata.InvokedBy = "aws-called-via-override.ecs.amazonaws.com"
	ctx = awsctx.WithMetadata(ctx, metadata)
	// TODO: Comeback match native regional linked-role discovery attempts;
	// an existing global role currently bypasses IAM creation.
	err := s.roles.EnsureServiceLinkedRole(ctx, ServicePrincipal)
	var rejected *awswire.Error
	if !errors.As(err, &rejected) || rejected.Code != "AccessDenied" {
		return err
	}
	// CreateCluster succeeds without this permission; a later creation request
	// can provision the still-absent role. Keep the denied IAM attempt observable.
	var completion interface{ RecordRejection(context.Context) error }
	if errors.As(err, &completion) {
		return completion.RecordRejection(ctx)
	}
	return nil
}

// WithClusterRoleUsage excludes cluster mutations while IAM completes its role
// deletion decision. Both provisioning and deletion acquire ECS before IAM.
func (s *Service) WithClusterRoleUsage(ctx context.Context, partition, accountID string, fn func(context.Context, []ClusterKey) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		keys, err := tx.ActiveClusterKeys(partition, accountID)
		if err != nil {
			return err
		}
		return fn(tx.Context(), keys)
	})
}
