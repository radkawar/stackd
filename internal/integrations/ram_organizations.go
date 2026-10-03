package integrations

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/awsapi"
	orgapi "stackd/internal/awsapi/organizations"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
	"stackd/storage/organizations"
)

const ramServicePrincipal = "ram.amazonaws.com"
const ramServiceRole = "AWSServiceRoleForResourceAccessManager"

// RAMOrganizations reads the actual organization hierarchy and IAM role, not a
// parallel RAM membership cache. All related operations borrow the RAM transaction.
type RAMOrganizations struct {
	Storage            organizations.Storage
	IdentityRepository iam.Repository
	Organizations      interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	}
	IAM interface {
		EnsureServiceLinkedRole(context.Context, string) error
	}
}

func ramOrganizationError(message string) error {
	return &awswire.Error{Code: "OperationNotPermittedException", Message: message, StatusCode: 400}
}

func (a RAMOrganizations) EnableSharing(ctx context.Context, owner string) (bool, error) {
	if a.Storage == nil || a.IdentityRepository == nil || a.Organizations == nil || a.IAM == nil {
		return false, ramOrganizationError("Organizations sharing is not configured.")
	}
	m := awsctx.FromContext(ctx)
	if owner != m.AccountID {
		return false, ramOrganizationError("Only the current organization management account can enable sharing.")
	}
	err := a.IdentityRepository.Update(ctx, func(tx iam.WriteTx) error {
		model, _ := awscatalog.LookupService("organizations")
		op, _ := model.Operation("DescribeOrganization")
		out, rejected := a.Organizations.ExecuteCommand(tx.Context(), awsapi.DecodedRequest{Operation: op, Input: &orgapi.DescribeOrganizationInput{}})
		if rejected != nil {
			return rejected
		}
		org, ok := out.(*orgapi.DescribeOrganizationOutput)
		if !ok || org.Organization == nil || org.Organization.MasterAccountId == nil || string(*org.Organization.MasterAccountId) != owner || org.Organization.FeatureSet == nil || string(*org.Organization.FeatureSet) != "ALL" {
			return ramOrganizationError("Enable sharing from an all-features organization's management account.")
		}
		metadata := awsctx.FromContext(tx.Context())
		metadata.InvokedBy = ramServicePrincipal
		child := awsctx.WithMetadata(tx.Context(), metadata)
		if err := a.IAM.EnsureServiceLinkedRole(child, ramServicePrincipal); err != nil {
			return err
		}
		op, _ = model.Operation("EnableAWSServiceAccess")
		_, rejected = a.Organizations.ExecuteCommand(child, awsapi.DecodedRequest{Operation: op, Input: &orgapi.EnableAWSServiceAccessInput{ServicePrincipal: new(orgapi.ServicePrincipal(ramServicePrincipal))}})
		if rejected != nil {
			return rejected
		}
		return nil
	})
	return err == nil, err
}

// Eligible checks current membership, active accounts, trusted access and the
// service-linked role. recipient=="" validates an organization/OU principal.
func (a RAMOrganizations) Eligible(ctx context.Context, owner, principal, recipient string) (bool, error) {
	isOrganization := strings.HasPrefix(principal, "arn:") && strings.Contains(principal, ":organizations:")
	if a.Storage == nil || a.IdentityRepository == nil {
		if isOrganization && recipient == "" {
			return false, ramOrganizationError("Organizations sharing is not configured.")
		}
		return false, nil
	}
	partition := awsctx.FromContext(ctx).Partition
	record, _, err := a.Storage.Load(ctx, partition)
	if err != nil {
		return false, err
	}
	for _, org := range record.Organizations {
		if org.Organization.FeatureSet != "ALL" || !ramActiveAccount(org, owner) {
			continue
		}
		trusted := false
		for _, access := range org.Services {
			if access.Principal == ramServicePrincipal {
				trusted = true
				break
			}
		}
		if !trusted {
			break
		}
		present := false
		err := a.IdentityRepository.View(ctx, func(r iam.ReadTx) error {
			role, err := r.Role(iam.Scope{Partition: partition, AccountID: org.Organization.MasterAccountID}, ramServiceRole)
			if errors.Is(err, iam.ErrRecordNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			present = role.ServiceLinkedService == ramServicePrincipal
			return nil
		})
		if err != nil {
			return false, err
		}
		if !present {
			break
		}
		if !isOrganization {
			return recipient != "" && ramActiveAccount(org, recipient), nil
		}
		if principal == org.Organization.ARN {
			return recipient == "" || ramActiveAccount(org, recipient), nil
		}
		unit := ""
		for _, candidate := range org.Units {
			if candidate.ARN == principal {
				unit = candidate.ID
				break
			}
		}
		if unit == "" {
			break
		}
		if recipient == "" {
			return true, nil
		}
		if !ramActiveAccount(org, recipient) {
			return false, nil
		}
		parents := make(map[string]string, len(org.Parents))
		for _, parent := range org.Parents {
			parents[parent.ChildID] = parent.ParentID
		}
		for parent := parents[recipient]; parent != ""; parent = parents[parent] {
			if parent == unit {
				return true, nil
			}
		}
		return false, nil
	}
	if isOrganization && recipient == "" {
		return false, ramOrganizationError("The principal must belong to the owner's current organization with RAM sharing enabled.")
	}
	return false, nil
}

func ramActiveAccount(org organizations.OrganizationRecord, id string) bool {
	for _, account := range org.Accounts {
		if account.ID == id {
			return account.State == "ACTIVE"
		}
	}
	return false
}

// WithServiceLinkedRoleUsage prevents deletion while trusted RAM sharing is on.
// Disabling trusted access immediately revokes organization grants and releases
// this dependency; IAM retains ownership of deletion and identity protection.
func (a RAMOrganizations) WithServiceLinkedRoleUsage(ctx context.Context, ref iam.ServiceLinkedRoleReference, fn func(context.Context, []iam.ServiceLinkedRoleUsage) error) error {
	return a.IdentityRepository.Update(ctx, func(tx iam.WriteTx) error {
		record, _, err := a.Storage.Load(tx.Context(), ref.Scope.Partition)
		if err != nil {
			return err
		}
		for _, org := range record.Organizations {
			if org.Organization.MasterAccountID != ref.Scope.AccountID {
				continue
			}
			for _, access := range org.Services {
				if access.Principal == ramServicePrincipal {
					return fn(tx.Context(), []iam.ServiceLinkedRoleUsage{{Region: "us-east-1", ResourceARNs: []string{org.Organization.ARN}}})
				}
			}
		}
		return fn(tx.Context(), nil)
	})
}
