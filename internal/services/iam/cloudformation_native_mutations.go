package iam

import (
	api "stackd/internal/awsapi/iam"
	"stackd/internal/awswire"
)

// Private native claims are checked inside IAM's authorized transaction. A
// prior Get cannot authorize a later same-name resource incarnation.
func cloudFormationNativeMutation(a *account, o CloudFormationContext, input any) *awswire.Error {
	if o.Direct {
		return nil
	}
	kind, name := "", ""
	switch in := input.(type) {
	case *api.GetUserInput:
		kind, name = "User", inputString(in.UserName)
	case *api.GetInstanceProfileInput:
		kind, name = "InstanceProfile", inputString(in.InstanceProfileName)
	case *api.GetPolicyInput:
		kind, name = "ManagedPolicy", inputString(in.PolicyArn)
	case *api.GetOpenIDConnectProviderInput:
		kind, name = "OIDCProvider", inputString(in.OpenIDConnectProviderArn)
	case *api.GetSAMLProviderInput:
		kind, name = "SAMLProvider", inputString(in.SAMLProviderArn)
	case *api.GetServerCertificateInput:
		kind, name = "ServerCertificate", inputString(in.ServerCertificateName)
	case *api.ListMFADeviceTagsInput:
		kind, name = "VirtualMFADevice", inputString(in.SerialNumber)
	case *api.UpdateUserInput:
		kind, name = "User", inputString(in.UserName)
	case *api.DeleteUserInput:
		kind, name = "User", inputString(in.UserName)
	case *api.TagUserInput:
		kind, name = "User", inputString(in.UserName)
	case *api.UntagUserInput:
		kind, name = "User", inputString(in.UserName)
	case *api.PutUserPermissionsBoundaryInput:
		kind, name = "User", inputString(in.UserName)
	case *api.DeleteUserPermissionsBoundaryInput:
		kind, name = "User", inputString(in.UserName)
	case *api.CreateLoginProfileInput:
		kind, name = "User", inputString(in.UserName)
	case *api.UpdateLoginProfileInput:
		kind, name = "User", inputString(in.UserName)
	case *api.DeleteLoginProfileInput:
		kind, name = "User", inputString(in.UserName)
	case *api.UpdateRoleInput:
		kind, name = "Role", inputString(in.RoleName)
	case *api.UpdateAssumeRolePolicyInput:
		kind, name = "Role", inputString(in.RoleName)
	case *api.DeleteRoleInput:
		kind, name = "Role", inputString(in.RoleName)
	case *api.TagRoleInput:
		kind, name = "Role", inputString(in.RoleName)
	case *api.UntagRoleInput:
		kind, name = "Role", inputString(in.RoleName)
	case *api.PutRolePermissionsBoundaryInput:
		kind, name = "Role", inputString(in.RoleName)
	case *api.DeleteRolePermissionsBoundaryInput:
		kind, name = "Role", inputString(in.RoleName)
	case *api.AddRoleToInstanceProfileInput:
		kind, name = "InstanceProfile", inputString(in.InstanceProfileName)
	case *api.RemoveRoleFromInstanceProfileInput:
		kind, name = "InstanceProfile", inputString(in.InstanceProfileName)
	case *api.DeleteInstanceProfileInput:
		kind, name = "InstanceProfile", inputString(in.InstanceProfileName)
	case *api.TagInstanceProfileInput:
		kind, name = "InstanceProfile", inputString(in.InstanceProfileName)
	case *api.UntagInstanceProfileInput:
		kind, name = "InstanceProfile", inputString(in.InstanceProfileName)
	case *api.CreatePolicyVersionInput:
		kind, name = "ManagedPolicy", inputString(in.PolicyArn)
	case *api.DeletePolicyVersionInput:
		kind, name = "ManagedPolicy", inputString(in.PolicyArn)
	case *api.SetDefaultPolicyVersionInput:
		kind, name = "ManagedPolicy", inputString(in.PolicyArn)
	case *api.DeletePolicyInput:
		kind, name = "ManagedPolicy", inputString(in.PolicyArn)
	case *api.TagPolicyInput:
		kind, name = "ManagedPolicy", inputString(in.PolicyArn)
	case *api.UntagPolicyInput:
		kind, name = "ManagedPolicy", inputString(in.PolicyArn)
	case *api.AddClientIDToOpenIDConnectProviderInput:
		kind, name = "OIDCProvider", inputString(in.OpenIDConnectProviderArn)
	case *api.RemoveClientIDFromOpenIDConnectProviderInput:
		kind, name = "OIDCProvider", inputString(in.OpenIDConnectProviderArn)
	case *api.UpdateOpenIDConnectProviderThumbprintInput:
		kind, name = "OIDCProvider", inputString(in.OpenIDConnectProviderArn)
	case *api.DeleteOpenIDConnectProviderInput:
		kind, name = "OIDCProvider", inputString(in.OpenIDConnectProviderArn)
	case *api.TagOpenIDConnectProviderInput:
		kind, name = "OIDCProvider", inputString(in.OpenIDConnectProviderArn)
	case *api.UntagOpenIDConnectProviderInput:
		kind, name = "OIDCProvider", inputString(in.OpenIDConnectProviderArn)
	case *api.UpdateSAMLProviderInput:
		kind, name = "SAMLProvider", inputString(in.SAMLProviderArn)
	case *api.DeleteSAMLProviderInput:
		kind, name = "SAMLProvider", inputString(in.SAMLProviderArn)
	case *api.TagSAMLProviderInput:
		kind, name = "SAMLProvider", inputString(in.SAMLProviderArn)
	case *api.UntagSAMLProviderInput:
		kind, name = "SAMLProvider", inputString(in.SAMLProviderArn)
	case *api.EnableMFADeviceInput:
		kind, name = "VirtualMFADevice", inputString(in.SerialNumber)
	case *api.DeactivateMFADeviceInput:
		kind, name = "VirtualMFADevice", inputString(in.SerialNumber)
	case *api.DeleteVirtualMFADeviceInput:
		kind, name = "VirtualMFADevice", inputString(in.SerialNumber)
	case *api.TagMFADeviceInput:
		kind, name = "VirtualMFADevice", inputString(in.SerialNumber)
	case *api.UntagMFADeviceInput:
		kind, name = "VirtualMFADevice", inputString(in.SerialNumber)
	case *api.UpdateServerCertificateInput:
		kind, name = "ServerCertificate", inputString(in.ServerCertificateName)
	case *api.DeleteServerCertificateInput:
		kind, name = "ServerCertificate", inputString(in.ServerCertificateName)
	case *api.TagServerCertificateInput:
		kind, name = "ServerCertificate", inputString(in.ServerCertificateName)
	case *api.UntagServerCertificateInput:
		kind, name = "ServerCertificate", inputString(in.ServerCertificateName)
	default:
		return nil
	}
	owner, err := cloudFormationNativeOwner(a, kind, name)
	if err != nil {
		return err
	}
	return checkCloudFormationOwner(o, owner)
}

func cloudFormationNativeOwner(a *account, kind, name string) (string, *awswire.Error) {
	switch kind {
	case "User":
		r, err := findUser(a, name)
		if err != nil {
			return "", err
		}
		return r.CloudFormationOwner, nil
	case "Role":
		r, err := findRole(a, name)
		if err != nil {
			return "", err
		}
		return r.CloudFormationOwner, nil
	case "InstanceProfile":
		r, err := findInstanceProfile(a, name)
		if err != nil {
			return "", err
		}
		return r.CloudFormationOwner, nil
	case "ManagedPolicy":
		r, err := findPolicyARN(a, name)
		if err != nil {
			return "", err
		}
		return r.CloudFormationOwner, nil
	case "OIDCProvider":
		r, err := findOIDCProvider(a, name)
		if err != nil {
			return "", err
		}
		return r.CloudFormationOwner, nil
	case "SAMLProvider":
		r, err := findSAMLProvider(a, name)
		if err != nil {
			return "", err
		}
		return r.CloudFormationOwner, nil
	case "VirtualMFADevice":
		r, err := findMFADevice(a, name)
		if err != nil {
			return "", err
		}
		return r.CloudFormationOwner, nil
	case "ServerCertificate":
		r, err := findServerCertificate(a, name)
		if err != nil {
			return "", err
		}
		return r.CloudFormationOwner, nil
	}
	return "", invalid("Unknown CloudFormation resource kind.")
}
