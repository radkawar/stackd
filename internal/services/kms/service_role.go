package kms

import (
	"context"
	"errors"
	"slices"

	"stackd/internal/awswire"
)

const MultiRegionServicePrincipal = "mrk.kms.amazonaws.com"
const MultiRegionServiceRoleName = "AWSServiceRoleForKeyManagementServiceMultiRegionKeys"

// ServiceRoles provisions protected IAM roles, authorizing creation only when
// the role does not exist. IAM owns the role independently of any one KMS key.
type ServiceRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

func (s *Service) ensureMultiRegionRole(ctx context.Context) *awswire.Error {
	if s.roles == nil {
		return failure("UnsupportedOperationException", "Multi-Region keys require an IAM service-role provider.")
	}
	if err := s.roles.EnsureServiceLinkedRole(ctx, MultiRegionServicePrincipal); err != nil {
		var rejected interface{ RecordRejection(context.Context) error }
		if errors.As(err, &rejected) {
			if audit, _ := ctx.Value(auditContextKey{}).(*auditContext); audit != nil {
				audit.roleRejection = rejected
			}
		}
		var apiErr *awswire.Error
		if errors.As(err, &apiErr) && apiErr.Code == "AccessDenied" {
			return failure("AccessDeniedException", apiErr.Message)
		}
		if errors.As(err, &apiErr) && apiErr.Code == "NotImplemented" {
			return failure("UnsupportedOperationException", apiErr.Message)
		}
		return failure("KMSInternalException", "Unable to provision the KMS multi-Region service-linked role.")
	}
	return nil
}

// WithMultiRegionKeys keeps regional dependencies stable while IAM completes
// its deletion decision. Creation and deletion both acquire KMS before IAM.
// TODO: Comeback capture final key deletion and unused KMS service-role deletion after the owned AWS deletion windows expire.
func (s *Service) WithMultiRegionKeys(ctx context.Context, owner KeyOwner, fn func(context.Context, map[string][]string) error) error {
	var callbackErr error
	err := s.transact(ctx, func(ctx context.Context) *awswire.Error {
		regions, err := s.transaction.MultiRegionPrimaryRegions(owner)
		if err != nil {
			s.storageErr = err
			return nil
		}
		for _, region := range regions {
			s.scopedStore(scope{partition: owner.Partition, account: owner.AccountID, region: region})
		}
		if s.storageErr != nil {
			return nil
		}
		usage := make(map[string][]string)
		for ref, set := range s.keySets {
			if ref.owner != owner || set == nil || !set.MultiRegion {
				continue
			}
			for _, region := range append(slices.Clone(set.ReplicaRegions), set.PrimaryRegion) {
				sc := scope{partition: owner.Partition, account: owner.AccountID, region: region}
				usage[region] = append(usage[region], sc.arn("key/"+set.ID))
			}
		}
		for _, arns := range usage {
			slices.Sort(arns)
		}
		callbackErr = fn(ctx, usage)
		if callbackErr != nil {
			s.storageErr = callbackErr
		}
		return nil
	})
	if callbackErr != nil {
		return callbackErr
	}
	if err != nil {
		return err
	}
	return nil
}
