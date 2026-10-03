package iam

import (
	"context"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// IAM's native policy parameters are JSON strings, not embedded documents; the
// returned role trust policy is already percent-encoded by generatedRole. Keep
// both representations intact (service_management_events.json, CreateRole and
// PutRolePolicy). IAM timestamps in audit responses use UTC RFC3339.
var iamAuditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Password":            {Mode: awsapi.OmitField},
	"OldPassword":         {Mode: awsapi.OmitField},
	"NewPassword":         {Mode: awsapi.OmitField},
	"AuthenticationCode1": {Mode: awsapi.OmitField},
	"AuthenticationCode2": {Mode: awsapi.OmitField},
	"PrivateKey":          {Mode: awsapi.OmitField},
	"AddPrivateKey":       {Mode: awsapi.OmitField},
	"DelegationToken":     {Mode: awsapi.OmitField},
}}

var iamAuditResponse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"AccessKey.SecretAccessKey":                         {Mode: awsapi.OmitField},
	"ServiceSpecificCredential.ServicePassword":         {Mode: awsapi.OmitField},
	"ServiceSpecificCredential.ServiceCredentialSecret": {Mode: awsapi.OmitField},
	"VirtualMFADevice.Base32StringSeed":                 {Mode: awsapi.OmitField},
	"VirtualMFADevice.QRCodePNG":                        {Mode: awsapi.OmitField},
	"User.CreateDate":                                   {TimeLayout: time.RFC3339},
	"Role.CreateDate":                                   {TimeLayout: time.RFC3339},
	"Group.CreateDate":                                  {TimeLayout: time.RFC3339},
	"AccessKey.CreateDate":                              {TimeLayout: time.RFC3339},
	"Policy.CreateDate":                                 {TimeLayout: time.RFC3339},
	"Policy.UpdateDate":                                 {TimeLayout: time.RFC3339},
	"PolicyVersion.CreateDate":                          {TimeLayout: time.RFC3339},
	"LoginProfile.CreateDate":                           {TimeLayout: time.RFC3339},
	"InstanceProfile.CreateDate":                        {TimeLayout: time.RFC3339},
	"ServiceSpecificCredential.CreateDate":              {TimeLayout: time.RFC3339},
	"ServiceSpecificCredential.ExpirationDate":          {TimeLayout: time.RFC3339},
	"Certificate.UploadDate":                            {TimeLayout: time.RFC3339},
	"SSHPublicKey.UploadDate":                           {TimeLayout: time.RFC3339},
	"ServerCertificateMetadata.UploadDate":              {TimeLayout: time.RFC3339},
	"ServerCertificateMetadata.Expiration":              {TimeLayout: time.RFC3339},
}}

// Classification is source-owned, not inferred from an operation-name prefix.
// The IAM logging guide specifies null read responses; its documented read-only
// response exceptions are STS assumption commands, not IAM commands. Newer IAM
// operations without an owned native capture follow that documented contract.
func iamAuditProjection(action string) apievents.Projection {
	p := apievents.Projection{Category: journal.CategoryManagement, Request: iamAuditRequest}
	switch action {
	case "GetAccessKeyLastUsed", "GetAccountAuthorizationDetails", "GetAccountPasswordPolicy",
		"GetAccountProperties", "GetAccountSummary", "GetContextKeysForCustomPolicy",
		"GetContextKeysForPrincipalPolicy", "GetCredentialReport", "GetDelegationRequest",
		"GetGroup", "GetGroupPolicy", "GetHumanReadableSummary", "GetInstanceProfile",
		"GetLoginProfile", "GetMFADevice", "GetOpenIDConnectProvider", "GetOrganizationsAccessReport",
		"GetOutboundWebIdentityFederationInfo", "GetPolicy", "GetPolicyVersion", "GetRole",
		"GetRolePolicy", "GetRoleTemplateVersion", "GetSAMLProvider", "GetSSHPublicKey",
		"GetServerCertificate", "GetServiceLastAccessedDetails", "GetServiceLastAccessedDetailsWithEntities",
		"GetServiceLinkedRoleDeletionStatus", "GetUser", "GetUserPolicy", "ListAccessKeys",
		"ListAccountAliases", "ListAttachedGroupPolicies", "ListAttachedRolePolicies",
		"ListAttachedUserPolicies", "ListDelegationRequests", "ListEntitiesForPolicy",
		"ListGroupPolicies", "ListGroups", "ListGroupsForUser", "ListInstanceProfileTags",
		"ListInstanceProfiles", "ListInstanceProfilesForRole", "ListMFADeviceTags", "ListMFADevices",
		"ListOpenIDConnectProviderTags", "ListOpenIDConnectProviders", "ListOrganizationsFeatures",
		"ListPolicies", "ListPoliciesGrantingServiceAccess", "ListPolicyTags", "ListPolicyVersions",
		"ListRolePolicies", "ListRoleTags", "ListRoles", "ListSAMLProviderTags", "ListSAMLProviders",
		"ListSSHPublicKeys", "ListServerCertificateTags", "ListServerCertificates",
		"ListServiceSpecificCredentials", "ListSigningCertificates", "ListUserPolicies", "ListUserTags",
		"ListUsers", "ListVirtualMFADevices", "SimulateCustomPolicy", "SimulatePrincipalPolicy":
		p.ReadOnly = true
	}
	// Response presence is explicit and independent of classification. Unit
	// mutation responses stay null; generated-shape projection removes secrets.
	switch action {
	case "AcquireRole", "CreateAccessKey", "CreateDelegationRequest", "CreateGroup",
		"CreateInstanceProfile", "CreateLoginProfile", "CreateOpenIDConnectProvider",
		"CreatePolicy", "CreatePolicyVersion", "CreateRole", "CreateSAMLProvider",
		"CreateServiceLinkedRole", "CreateServiceSpecificCredential", "CreateUser",
		"CreateVirtualMFADevice", "DeleteServiceLinkedRole", "GenerateCredentialReport",
		"GenerateOrganizationsAccessReport", "GenerateServiceLastAccessedDetails",
		"ResetServiceSpecificCredential", "UpdateRoleDescription", "UpdateSAMLProvider",
		"UploadSSHPublicKey", "UploadServerCertificate", "UploadSigningCertificate",
		"EnableOrganizationsRootCredentialsManagement", "DisableOrganizationsRootCredentialsManagement",
		"EnableOrganizationsRootSessions", "DisableOrganizationsRootSessions",
		"EnableOutboundWebIdentityFederation":
		p.Response = &iamAuditResponse
	}
	return p
}

func (s *Service) appendAPICall(ctx context.Context, at time.Time, result any, apiErr *awswire.Error) error {
	if s.apiCallEvents == nil {
		return nil
	}
	decoded, ok := awsapi.FromContext(ctx)
	if !ok {
		return nil
	}
	model, _ := awscatalog.LookupService("iam")
	op, known := model.Operation(string(decoded.Operation.Name))
	if !known {
		return nil
	}
	p := iamAuditProjection(string(op.Name))
	call, err := p.Call(model, op, decoded.Input, result, apiErr)
	if err != nil {
		return err
	}
	if apiErr == nil && !p.ReadOnly {
		call.Resources = iamAuditResources(decoded.Input, result)
	}
	// Lookup aliases are not document resources. Native IAM captures omit the
	// resources member even when the LookupEvents wrapper has several aliases.
	m := awsctx.FromContext(ctx)
	// TODO: Comeback complete global IAM history-region routing and partition-specific native captures.
	return s.apiCallEvents.Record(ctx, journal.Envelope{At: at, Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, call)
}

// RecordRequestError is also used for authenticated gateway restrictions and
// malformed known commands. Failed bodies are never retained or reparsed.
func (s *Service) RecordRequestError(ctx context.Context, decoded awsapi.DecodedRequest, failure *awswire.Error) error {
	return s.appendAPICall(awsapi.WithDecodedRequest(ctx, decoded), s.clock.Now(), nil, failure)
}

func iamAuditResources(input, result any) []journal.APIResource {
	var resources []journal.APIResource
	add := func(kind string, names ...string) {
		for _, name := range names {
			if name != "" {
				resources = append(resources, journal.APIResource{Type: "AWS::IAM::" + kind, Name: name})
			}
		}
	}
	role := func(r *api.Role) {
		if r != nil {
			add("Role", inputString(r.RoleName), inputString(r.RoleId), inputString(r.Arn))
		}
	}
	switch out := result.(type) {
	case *api.CreateUserOutput:
		if u := out.User; u != nil {
			add("User", inputString(u.Arn), inputString(u.UserName), inputString(u.UserId))
		}
		return resources
	case *api.CreateRoleOutput:
		role(out.Role)
		return resources
	case *api.CreateServiceLinkedRoleOutput:
		role(out.Role)
		return resources
	case *api.AcquireRoleOutput:
		role(out.Role)
		return resources
	case *api.CreateAccessKeyOutput:
		if k := out.AccessKey; k != nil {
			add("AccessKey", inputString(k.AccessKeyId))
			add("User", inputString(k.UserName))
		}
		return resources
	case *api.CreateGroupOutput:
		if g := out.Group; g != nil {
			add("Group", inputString(g.GroupName), inputString(g.GroupId), inputString(g.Arn))
		}
		return resources
	case *api.CreatePolicyOutput:
		if p := out.Policy; p != nil {
			add("Policy", inputString(p.PolicyName), inputString(p.PolicyId), inputString(p.Arn))
		}
		return resources
	case *api.CreateInstanceProfileOutput:
		if p := out.InstanceProfile; p != nil {
			add("InstanceProfile", inputString(p.InstanceProfileName), inputString(p.InstanceProfileId), inputString(p.Arn))
		}
		return resources
	case *api.CreateOpenIDConnectProviderOutput:
		add("OIDCProvider", inputString(out.OpenIDConnectProviderArn))
		return resources
	case *api.CreateSAMLProviderOutput:
		add("SAMLProvider", inputString(out.SAMLProviderArn))
		return resources
	case *api.CreateVirtualMFADeviceOutput:
		if d := out.VirtualMFADevice; d != nil {
			add("MFADevice", inputString(d.SerialNumber))
		}
		return resources
	case *api.UploadServerCertificateOutput:
		if c := out.ServerCertificateMetadata; c != nil {
			add("ServerCertificate", inputString(c.ServerCertificateName), inputString(c.ServerCertificateId), inputString(c.Arn))
		}
		return resources
	}
	// Native role-policy mutations index the policy name before the role name;
	// failed calls and all reads have no lookup aliases.
	switch in := input.(type) {
	case *api.UpdateUserInput:
		add("User", inputString(in.UserName))
	case *api.DeleteUserInput:
		add("User", inputString(in.UserName))
	case *api.UpdateAccessKeyInput:
		add("AccessKey", inputString(in.AccessKeyId))
		add("User", inputString(in.UserName))
	case *api.DeleteAccessKeyInput:
		add("AccessKey", inputString(in.AccessKeyId))
		add("User", inputString(in.UserName))
	case *api.UpdateRoleInput:
		add("Role", inputString(in.RoleName))
	case *api.UpdateRoleDescriptionInput:
		add("Role", inputString(in.RoleName))
	case *api.UpdateAssumeRolePolicyInput:
		add("Role", inputString(in.RoleName))
	case *api.DeleteRoleInput:
		add("Role", inputString(in.RoleName))
	case *api.DeleteServiceLinkedRoleInput:
		add("Role", inputString(in.RoleName))
	case *api.PutRolePolicyInput:
		add("Policy", inputString(in.PolicyName))
		add("Role", inputString(in.RoleName))
	case *api.DeleteRolePolicyInput:
		add("Policy", inputString(in.PolicyName))
		add("Role", inputString(in.RoleName))
	case *api.PutUserPolicyInput:
		add("Policy", inputString(in.PolicyName))
		add("User", inputString(in.UserName))
	case *api.DeleteUserPolicyInput:
		add("Policy", inputString(in.PolicyName))
		add("User", inputString(in.UserName))
	case *api.PutGroupPolicyInput:
		add("Policy", inputString(in.PolicyName))
		add("Group", inputString(in.GroupName))
	case *api.DeleteGroupPolicyInput:
		add("Policy", inputString(in.PolicyName))
		add("Group", inputString(in.GroupName))
	case *api.AttachRolePolicyInput:
		add("Policy", inputString(in.PolicyArn))
		add("Role", inputString(in.RoleName))
	case *api.DetachRolePolicyInput:
		add("Policy", inputString(in.PolicyArn))
		add("Role", inputString(in.RoleName))
	case *api.AttachUserPolicyInput:
		add("Policy", inputString(in.PolicyArn))
		add("User", inputString(in.UserName))
	case *api.DetachUserPolicyInput:
		add("Policy", inputString(in.PolicyArn))
		add("User", inputString(in.UserName))
	case *api.AttachGroupPolicyInput:
		add("Policy", inputString(in.PolicyArn))
		add("Group", inputString(in.GroupName))
	case *api.DetachGroupPolicyInput:
		add("Policy", inputString(in.PolicyArn))
		add("Group", inputString(in.GroupName))
	case *api.CreatePolicyVersionInput:
		add("Policy", inputString(in.PolicyArn))
	case *api.DeletePolicyVersionInput:
		add("Policy", inputString(in.PolicyArn))
	case *api.SetDefaultPolicyVersionInput:
		add("Policy", inputString(in.PolicyArn))
	case *api.DeletePolicyInput:
		add("Policy", inputString(in.PolicyArn))
	case *api.UpdateGroupInput:
		add("Group", inputString(in.GroupName))
	case *api.DeleteGroupInput:
		add("Group", inputString(in.GroupName))
	case *api.AddUserToGroupInput:
		add("Group", inputString(in.GroupName))
		add("User", inputString(in.UserName))
	case *api.RemoveUserFromGroupInput:
		add("Group", inputString(in.GroupName))
		add("User", inputString(in.UserName))
	case *api.DeleteInstanceProfileInput:
		add("InstanceProfile", inputString(in.InstanceProfileName))
	case *api.AddRoleToInstanceProfileInput:
		add("InstanceProfile", inputString(in.InstanceProfileName))
		add("Role", inputString(in.RoleName))
	case *api.RemoveRoleFromInstanceProfileInput:
		add("InstanceProfile", inputString(in.InstanceProfileName))
		add("Role", inputString(in.RoleName))
	case *api.TagUserInput:
		add("User", inputString(in.UserName))
	case *api.UntagUserInput:
		add("User", inputString(in.UserName))
	case *api.TagRoleInput:
		add("Role", inputString(in.RoleName))
	case *api.UntagRoleInput:
		add("Role", inputString(in.RoleName))
	case *api.TagPolicyInput:
		add("Policy", inputString(in.PolicyArn))
	case *api.UntagPolicyInput:
		add("Policy", inputString(in.PolicyArn))
	case *api.TagInstanceProfileInput:
		add("InstanceProfile", inputString(in.InstanceProfileName))
	case *api.UntagInstanceProfileInput:
		add("InstanceProfile", inputString(in.InstanceProfileName))
	case *api.PutUserPermissionsBoundaryInput:
		add("User", inputString(in.UserName))
		add("Policy", inputString(in.PermissionsBoundary))
	case *api.DeleteUserPermissionsBoundaryInput:
		add("User", inputString(in.UserName))
	case *api.PutRolePermissionsBoundaryInput:
		add("Role", inputString(in.RoleName))
		add("Policy", inputString(in.PermissionsBoundary))
	case *api.DeleteRolePermissionsBoundaryInput:
		add("Role", inputString(in.RoleName))
	case *api.DeleteOpenIDConnectProviderInput:
		add("OIDCProvider", inputString(in.OpenIDConnectProviderArn))
	case *api.AddClientIDToOpenIDConnectProviderInput:
		add("OIDCProvider", inputString(in.OpenIDConnectProviderArn))
	case *api.RemoveClientIDFromOpenIDConnectProviderInput:
		add("OIDCProvider", inputString(in.OpenIDConnectProviderArn))
	case *api.UpdateOpenIDConnectProviderThumbprintInput:
		add("OIDCProvider", inputString(in.OpenIDConnectProviderArn))
	case *api.TagOpenIDConnectProviderInput:
		add("OIDCProvider", inputString(in.OpenIDConnectProviderArn))
	case *api.UntagOpenIDConnectProviderInput:
		add("OIDCProvider", inputString(in.OpenIDConnectProviderArn))
	case *api.DeleteSAMLProviderInput:
		add("SAMLProvider", inputString(in.SAMLProviderArn))
	case *api.UpdateSAMLProviderInput:
		add("SAMLProvider", inputString(in.SAMLProviderArn))
	case *api.TagSAMLProviderInput:
		add("SAMLProvider", inputString(in.SAMLProviderArn))
	case *api.UntagSAMLProviderInput:
		add("SAMLProvider", inputString(in.SAMLProviderArn))
	case *api.DeleteVirtualMFADeviceInput:
		add("MFADevice", inputString(in.SerialNumber))
	case *api.EnableMFADeviceInput:
		add("MFADevice", inputString(in.SerialNumber))
		add("User", inputString(in.UserName))
	case *api.DeactivateMFADeviceInput:
		add("MFADevice", inputString(in.SerialNumber))
		add("User", inputString(in.UserName))
	case *api.ResyncMFADeviceInput:
		add("MFADevice", inputString(in.SerialNumber))
		add("User", inputString(in.UserName))
	case *api.TagMFADeviceInput:
		add("MFADevice", inputString(in.SerialNumber))
	case *api.UntagMFADeviceInput:
		add("MFADevice", inputString(in.SerialNumber))
	case *api.CreateLoginProfileInput:
		add("User", inputString(in.UserName))
	case *api.UpdateLoginProfileInput:
		add("User", inputString(in.UserName))
	case *api.DeleteLoginProfileInput:
		add("User", inputString(in.UserName))
	case *api.DeleteServerCertificateInput:
		add("ServerCertificate", inputString(in.ServerCertificateName))
	case *api.UpdateServerCertificateInput:
		add("ServerCertificate", inputString(in.ServerCertificateName))
	case *api.TagServerCertificateInput:
		add("ServerCertificate", inputString(in.ServerCertificateName))
	case *api.UntagServerCertificateInput:
		add("ServerCertificate", inputString(in.ServerCertificateName))
	case *api.UploadSigningCertificateInput:
		add("User", inputString(in.UserName))
	case *api.UpdateSigningCertificateInput:
		add("User", inputString(in.UserName))
	case *api.DeleteSigningCertificateInput:
		add("User", inputString(in.UserName))
	case *api.UploadSSHPublicKeyInput:
		add("User", inputString(in.UserName))
	case *api.UpdateSSHPublicKeyInput:
		add("User", inputString(in.UserName))
	case *api.DeleteSSHPublicKeyInput:
		add("User", inputString(in.UserName))
	case *api.CreateServiceSpecificCredentialInput:
		add("User", inputString(in.UserName))
	case *api.ResetServiceSpecificCredentialInput:
		add("User", inputString(in.UserName))
	case *api.UpdateServiceSpecificCredentialInput:
		add("User", inputString(in.UserName))
	case *api.DeleteServiceSpecificCredentialInput:
		add("User", inputString(in.UserName))
	}
	return resources
}
