package integrations

import (
	"context"

	"stackd/internal/services/iam"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

// IAM resources share their native account-global namespace across Regions.
// Users and roles remain here for mutation resolution; the read APIs exclude them.
func (r ResourceTaggingResources) listTaggingIAM(ctx context.Context, scope tagging.Scope) (out []tagging.Resource, err error) {
	appendResource := func(arn, kind string, list []iam.Tag) {
		var tags map[string]string
		if len(list) != 0 {
			tags = make(map[string]string, len(list))
			for _, tag := range list {
				tags[tag.Key] = tag.Value
			}
		}
		out = append(out, tagging.Resource{ARN: arn, ResourceType: "iam:" + kind, Tags: tags})
	}
	err = r.Backends.IAM.View(ctx, func(tx iam.ReadTx) error {
		sc := iam.Scope{Partition: scope.Partition, AccountID: scope.AccountID}
		users, err := tx.Users(sc)
		if err != nil {
			return err
		}
		for _, row := range users {
			appendResource(row.Arn, "user", row.Tags)
		}
		roles, err := tx.Roles(sc)
		if err != nil {
			return err
		}
		for _, row := range roles {
			appendResource(row.Arn, "role", row.Tags)
		}
		policies, err := tx.ManagedPolicies(sc)
		if err != nil {
			return err
		}
		for _, row := range policies {
			appendResource(row.Arn, "policy", row.Tags)
		}
		profiles, err := tx.InstanceProfiles(sc)
		if err != nil {
			return err
		}
		for _, row := range profiles {
			appendResource(row.Arn, "instance-profile", row.Tags)
		}
		devices, err := tx.MFADevices(sc)
		if err != nil {
			return err
		}
		for _, row := range devices {
			if !row.RetiredAt.IsZero() {
				continue
			}
			appendResource(row.SerialNumber, "mfa", row.Tags)
		}
		oidc, err := tx.OIDCProviders(sc)
		if err != nil {
			return err
		}
		for _, row := range oidc {
			appendResource(row.ARN, "oidc-provider", row.Tags)
		}
		saml, err := tx.SAMLProviders(sc)
		if err != nil {
			return err
		}
		for _, row := range saml {
			appendResource(row.ARN, "saml-provider", row.Tags)
		}
		certificates, err := tx.ServerCertificates(sc)
		if err != nil {
			return err
		}
		for _, row := range certificates {
			appendResource(row.ARN, "server-certificate", row.Tags)
		}
		return nil
	})
	return
}

func (r ResourceTaggingResources) listTaggingOrganizations(ctx context.Context, scope tagging.Scope) ([]tagging.Resource, error) {
	partition, _, err := r.Backends.Organizations.Load(ctx, scope.Partition)
	if err != nil {
		return nil, err
	}
	var out []tagging.Resource
	for _, organization := range partition.Organizations {
		// Organizations ARNs are owned by the management account, not by every
		// member or delegated administrator that may have native list authority.
		if organization.Organization.MasterAccountID != scope.AccountID {
			continue
		}
		tags := make(map[string]map[string]string)
		for _, tag := range organization.Tags {
			if tags[tag.ResourceID] == nil {
				tags[tag.ResourceID] = make(map[string]string)
			}
			tags[tag.ResourceID][tag.Key] = tag.Value
		}
		appendResource := func(id, arn, kind string) {
			out = append(out, tagging.Resource{ARN: arn, ResourceType: "organizations:" + kind, Tags: tags[id]})
		}
		appendResource(organization.Root.ID, organization.Root.ARN, "root")
		for _, row := range organization.Accounts {
			appendResource(row.ID, row.ARN, "account")
		}
		for _, row := range organization.Units {
			appendResource(row.ID, row.ARN, "ou")
		}
		for _, row := range organization.Policies {
			if row.PolicySummary.AWSManaged {
				continue
			}
			appendResource(row.PolicySummary.ID, row.PolicySummary.ARN, "policy")
		}
		if policy := organization.ResourcePolicy; policy.ID != "" {
			appendResource(policy.ID, policy.ARN, "resourcepolicy")
		}
	}
	return out, nil
}
