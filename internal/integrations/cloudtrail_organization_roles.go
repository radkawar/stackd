package integrations

import (
	"context"
	"errors"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/iam"
	"stackd/storage/organizations"
)

const cloudTrailService = "cloudtrail.amazonaws.com"
const cloudTrailRole = "AWSServiceRoleForCloudTrail"

// CloudTrailOrganizationRoles composes authoritative membership with IAM's role
// lifecycle. IAM alone builds, stores and protects role identities and policies.
type CloudTrailOrganizationRoles struct {
	Organizations      organizations.Storage
	IdentityRepository iam.Repository
	Trails             cloudtrail.Repository
	IAM                interface {
		EnsureServiceLinkedRole(context.Context, string) error
		ProvisionServiceLinkedRole(context.Context, iam.Scope, string) error
		RemoveProvisionedServiceLinkedRole(context.Context, iam.Scope, string) error
	}
}

func (a CloudTrailOrganizationRoles) organization(ctx context.Context, partition, management string) (organizations.OrganizationRecord, error) {
	state, _, err := a.Organizations.Load(ctx, partition)
	if err != nil {
		return organizations.OrganizationRecord{}, err
	}
	for _, org := range state.Organizations {
		if org.Organization.MasterAccountID != management || org.Organization.FeatureSet != "ALL" {
			continue
		}
		for _, service := range org.Services {
			if service.Principal == cloudTrailService {
				return org, nil
			}
		}
	}
	return organizations.OrganizationRecord{}, &awswire.Error{Code: "CloudTrailAccessNotEnabledException", Message: "Current organization membership and CloudTrail trusted access are required.", StatusCode: 400}
}

func (a CloudTrailOrganizationRoles) EnsureOrganizationRoles(ctx context.Context, partition, management string) error {
	org, err := a.organization(ctx, partition, management)
	if err != nil {
		return err
	}
	m := awsctx.FromContext(ctx)
	if m.Partition != partition {
		return &awswire.Error{Code: "NotOrganizationMasterAccountException", Message: "Organization authority belongs to another partition.", StatusCode: 400}
	}
	if m.AccountID == management {
		// IAM checks creation permission only when the role does not exist.
		metadata := m
		metadata.InvokedBy = cloudTrailService
		if err := a.IAM.EnsureServiceLinkedRole(awsctx.WithMetadata(ctx, metadata), cloudTrailService); err != nil {
			return err
		}
	} else {
		active, delegated := false, false
		for _, account := range org.Accounts {
			if account.ID == m.AccountID && account.State == "ACTIVE" {
				active = true
			}
		}
		for _, delegate := range org.Delegations {
			if delegate.AccountID == m.AccountID && delegate.Principal == cloudTrailService {
				delegated = true
			}
		}
		if !active || !delegated {
			return &awswire.Error{Code: "NotOrganizationMasterAccountException", Message: "Current CloudTrail delegated administrator authority is required.", StatusCode: 400}
		}
		// Delegated administration cannot silently create the management role.
		err := a.IdentityRepository.View(ctx, func(tx iam.ReadTx) error {
			role, err := tx.Role(iam.Scope{Partition: partition, AccountID: management}, cloudTrailRole)
			if errors.Is(err, iam.ErrRecordNotFound) || err == nil && role.ServiceLinkedService != cloudTrailService {
				return &awswire.Error{Code: "NoManagementAccountSLRExistsException", Message: "The management account must first create the CloudTrail service-linked role.", StatusCode: 400}
			}
			return err
		})
		if err != nil {
			return err
		}
	}
	return a.provisionMembers(ctx, partition, org)
}

// ReconcileOrganizationRoles is invoked only by CloudTrail's committed
// Organizations journal consumer, never through a customer-facing IAM command.
func (a CloudTrailOrganizationRoles) ReconcileOrganizationRoles(ctx context.Context, partition, management string) error {
	org, err := a.organization(ctx, partition, management)
	if err != nil {
		return err
	}
	return a.provisionMembers(ctx, partition, org)
}

func (a CloudTrailOrganizationRoles) provisionMembers(ctx context.Context, partition string, org organizations.OrganizationRecord) error {
	for _, account := range org.Accounts {
		if account.ID == org.Organization.MasterAccountID || account.State != "ACTIVE" {
			continue
		}
		if err := a.IAM.ProvisionServiceLinkedRole(ctx, iam.Scope{Partition: partition, AccountID: account.ID}, cloudTrailService); err != nil {
			return err
		}
	}
	return nil
}

// RemoveMemberRole consumes a successful Organizations leave/removal outcome.
// Current membership is checked again so a rejoined account's role is preserved.
// IAM owns deletion, including protected identity and attached-policy cleanup.
func (a CloudTrailOrganizationRoles) RemoveMemberRole(ctx context.Context, partition, accountID string) error {
	state, _, err := a.Organizations.Load(ctx, partition)
	if err != nil {
		return err
	}
	for _, org := range state.Organizations {
		for _, account := range org.Accounts {
			if account.ID == accountID {
				return nil
			}
		}
	}
	return a.IAM.RemoveProvisionedServiceLinkedRole(ctx, iam.Scope{Partition: partition, AccountID: accountID}, cloudTrailService)
}

// WithServiceLinkedRoleUsage holds current membership and trail dependencies
// stable throughout IAM's deletion decision. Converting/deleting the last
// organization trail permits ordinary IAM deletion; no Lake state is owned here.
func (a CloudTrailOrganizationRoles) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.IdentityRepository.Update(ctx, func(tx iam.WriteTx) error {
		state, _, err := a.Organizations.Load(tx.Context(), ref.Scope.Partition)
		if err != nil {
			return err
		}
		for _, org := range state.Organizations {
			if org.Organization.FeatureSet != "ALL" {
				continue
			}
			member, trusted := false, false
			for _, account := range org.Accounts {
				if account.ID == ref.Scope.AccountID {
					member = true
				}
			}
			for _, service := range org.Services {
				if service.Principal == cloudTrailService {
					trusted = true
				}
			}
			if member && trusted {
				return a.Trails.View(tx.Context(), func(r cloudtrail.Reader) error {
					trails, err := r.Trails(ref.Scope.Partition, org.Organization.MasterAccountID)
					if err != nil {
						return err
					}
					var usage []iam.ServiceLinkedRoleUsage
					for _, trail := range trails {
						if trail.OrganizationID == org.Organization.ID {
							usage = append(usage, iam.ServiceLinkedRoleUsage{Region: trail.Key.Region, ResourceARNs: []string{trail.Key.ARN()}})
						}
					}
					return fn(r.Context(), usage)
				})
			}
		}
		return fn(tx.Context(), nil)
	})
}
