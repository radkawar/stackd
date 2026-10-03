package iam

import (
	"context"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

func (s *Service) getAccountSummary(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	rootKeys, err := s.credentialStore(ctx).ListAccessKeys(m.AccountID, m.AccountID)
	if err != nil {
		return nil, &awswire.Error{Code: "ServiceFailure", Message: "Unable to retrieve IAM account summary.", StatusCode: 500}
	}
	summary := iamapi.SummaryMapType{
		iamapi.SummaryKeyTypeUsers:                             iamapi.SummaryValueType(len(a.users)),
		iamapi.SummaryKeyTypeGroups:                            iamapi.SummaryValueType(len(a.groups)),
		iamapi.SummaryKeyTypeRoles:                             iamapi.SummaryValueType(len(a.roles)),
		iamapi.SummaryKeyTypeInstanceProfiles:                  iamapi.SummaryValueType(len(a.instanceProfiles)),
		iamapi.SummaryKeyTypeServerCertificates:                iamapi.SummaryValueType(len(a.serverCertificates)),
		iamapi.SummaryKeyTypePolicies:                          iamapi.SummaryValueType(localPolicyCount(a)),
		iamapi.SummaryKeyTypePolicyVersionsInUse:               iamapi.SummaryValueType(policyVersionsInUse(a)),
		iamapi.SummaryKeyTypeProviders:                         iamapi.SummaryValueType(len(a.samlProviders) + len(a.oidcProviders)),
		iamapi.SummaryKeyTypeMFADevices:                        iamapi.SummaryValueType(len(a.mfaDevices)),
		iamapi.SummaryKeyTypeMFADevicesInUse:                   0,
		iamapi.SummaryKeyTypeAccountMFAEnabled:                 0,
		iamapi.SummaryKeyTypeAccountAccessKeysPresent:          0,
		iamapi.SummaryKeyTypeAccountSigningCertificatesPresent: 0,
		iamapi.SummaryKeyTypeAccountPasswordPresent:            0,
		iamapi.SummaryKeyTypeGlobalEndpointTokenVersion:        1,
		iamapi.SummaryKeyTypeUsersQuota:                        maxUsers,
		iamapi.SummaryKeyTypeGroupsQuota:                       maxGroups,
		iamapi.SummaryKeyTypeRolesQuota:                        maxRoles,
		iamapi.SummaryKeyTypeInstanceProfilesQuota:             maxInstanceProfiles,
		iamapi.SummaryKeyTypeServerCertificatesQuota:           maxServerCertificates,
		iamapi.SummaryKeyTypePoliciesQuota:                     maxPolicies,
		iamapi.SummaryKeyTypePolicyVersionsInUseQuota:          maxPolicyVersionsInUse,
		iamapi.SummaryKeyTypeVersionsPerPolicyQuota:            maxVersionsPerPolicy,
		iamapi.SummaryKeyTypePolicySizeQuota:                   maxManagedPolicyCharacters,
		iamapi.SummaryKeyTypeAssumeRolePolicySizeQuota:         maxTrustPolicyCharacters,
		iamapi.SummaryKeyTypeUserPolicySizeQuota:               iamapi.SummaryValueType(inlinePolicyQuota("User")),
		iamapi.SummaryKeyTypeGroupPolicySizeQuota:              iamapi.SummaryValueType(inlinePolicyQuota("Group")),
		iamapi.SummaryKeyTypeRolePolicySizeQuota:               iamapi.SummaryValueType(inlinePolicyQuota("Role")),
		iamapi.SummaryKeyTypeAttachedPoliciesPerUserQuota:      maxAttachedPoliciesPerUser,
		iamapi.SummaryKeyTypeAttachedPoliciesPerGroupQuota:     maxAttachedPoliciesPerGroup,
		iamapi.SummaryKeyTypeAttachedPoliciesPerRoleQuota:      maxAttachedPoliciesPerRole,
		iamapi.SummaryKeyTypeGroupsPerUserQuota:                maxGroupsPerUser,
		iamapi.SummaryKeyTypeAccessKeysPerUserQuota:            identity.AccessKeysPerPrincipalQuota,
		iamapi.SummaryKeyTypeSigningCertificatesPerUserQuota:   maxSigningCertificatesPerUser,
	}
	if a.settings.GlobalEndpointAllRegions.Value {
		summary[iamapi.SummaryKeyTypeGlobalEndpointTokenVersion] = 2
	}
	// ListAccessKeys contains persisted long-term keys, including inactive keys.
	// Bootstrap signing fixtures and STS sessions are deliberately absent.
	if len(rootKeys) != 0 {
		summary[iamapi.SummaryKeyTypeAccountAccessKeysPresent] = 1
	}
	if a.settings.RootLoginProfile != nil {
		summary[iamapi.SummaryKeyTypeAccountPasswordPresent] = 1
	}
	rootARN := "arn:" + m.Partition + ":iam::" + m.AccountID + ":root"
	for _, certificate := range a.signingCertificates {
		if certificate.UserID == rootARN {
			summary[iamapi.SummaryKeyTypeAccountSigningCertificatesPresent] = 1
		}
	}
	for _, device := range a.mfaDevices {
		if device.Binding.Value.UserID != "" {
			summary[iamapi.SummaryKeyTypeMFADevicesInUse]++
		}
		if device.Binding.Value.UserID == m.AccountID {
			summary[iamapi.SummaryKeyTypeAccountMFAEnabled] = 1
		}
	}
	return &iamapi.GetAccountSummaryOutput{SummaryMap: summary}, nil
}

// IAM counts one current default version per distinct referenced managed
// policy, including AWS-owned policies and boundary-only references. Retained
// nondefault versions and policies without either reference do not contribute.
func policyVersionsInUse(a *account) int {
	used := make(map[string]struct{})
	add := func(p identityPolicies, b *boundary) {
		for arn := range p.Attached {
			used[arn] = struct{}{}
		}
		if b != nil && b.PermissionsBoundaryArn != "" {
			used[b.PermissionsBoundaryArn] = struct{}{}
		}
	}
	for _, u := range a.users {
		add(u.IdentityPolicies, u.PermissionsBoundary)
	}
	for _, g := range a.groups {
		add(g.IdentityPolicies, nil)
	}
	for _, r := range a.roles {
		add(r.IdentityPolicies, r.PermissionsBoundary)
	}
	return len(used)
}
