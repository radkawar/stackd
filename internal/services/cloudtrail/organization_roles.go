package cloudtrail

import (
	"context"
	"errors"

	"stackd/internal/awswire"
)

// OrganizationRoles owns no identities. Admission uses current caller authority;
// reconciliation is a service-owned consequence of committed membership changes.
// Both calls join the supplied transaction and use IAM's protected role builder.
type OrganizationRoles interface {
	EnsureOrganizationRoles(context.Context, string, string) error
	ReconcileOrganizationRoles(context.Context, string, string) error
	RemoveMemberRole(context.Context, string, string) error
}

func (s *Service) ensureOrganizationRoles(ctx context.Context, trail TrailRecord) error {
	if trail.OrganizationID == "" {
		return nil
	}
	if s.organizationRoles == nil {
		return unsupported("No organization service-linked role provisioner is configured.")
	}
	return s.organizationRoles.EnsureOrganizationRoles(ctx, trail.Key.Partition, trail.Key.AccountID)
}

func (s *Service) organizationDependencyError(ctx context.Context, err error) *awswire.Error {
	var rejected interface{ RecordRejection(context.Context) error }
	if errors.As(err, &rejected) {
		if recordErr := rejected.RecordRejection(ctx); recordErr != nil {
			return storageFailure()
		}
	}
	wire := wireError(err)
	if wire != nil && (wire.Code == "AccessDenied" || wire.Code == "AccessDeniedException") {
		return failure("InsufficientDependencyServiceAccessPermissionException", "CloudTrail could not create its organization service-linked role.")
	}
	return wire
}
