package iam

import (
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
)

// Names select stored records; the records supply canonical names and paths.
// The generated accessors expose only members accepted by the operation.
func authorizationResourceName(input any, kind string) string {
	switch kind {
	case "user":
		if in, ok := input.(interface{ ResourceUserName() *string }); ok {
			return inputString(in.ResourceUserName())
		}
	case "group":
		if in, ok := input.(interface{ ResourceGroupName() *string }); ok {
			return inputString(in.ResourceGroupName())
		}
	case "role":
		if in, ok := input.(interface{ ResourceRoleName() *string }); ok {
			return inputString(in.ResourceRoleName())
		}
	case "server-certificate":
		if in, ok := input.(interface{ ResourceServerCertificateName() *string }); ok {
			return inputString(in.ResourceServerCertificateName())
		}
	case "instance-profile":
		if in, ok := input.(interface{ ResourceInstanceProfileName() *string }); ok {
			return inputString(in.ResourceInstanceProfileName())
		}
	case "mfa", "sms-mfa":
		if in, ok := input.(interface{ ResourceSerialNumber() *string }); ok {
			return inputString(in.ResourceSerialNumber())
		}
	}
	return ""
}

// Creation authorizes the requested path before a resource record exists.
func creationAuthorizationResource(input any, m awsctx.Metadata, kind string) (string, bool) {
	var name, path string
	switch in := input.(type) {
	case *iamapi.CreateUserInput:
		name, path = inputString(in.UserName), inputString(in.Path)
	case *iamapi.CreateGroupInput:
		name, path = inputString(in.GroupName), inputString(in.Path)
	case *iamapi.CreateRoleInput:
		name, path = inputString(in.RoleName), inputString(in.Path)
	case *iamapi.CreatePolicyInput:
		name, path = inputString(in.PolicyName), inputString(in.Path)
	case *iamapi.CreateInstanceProfileInput:
		name, path = inputString(in.InstanceProfileName), inputString(in.Path)
	case *iamapi.CreateVirtualMFADeviceInput:
		name, path = inputString(in.VirtualMFADeviceName), inputString(in.Path)
	case *iamapi.UploadServerCertificateInput:
		name, path = inputString(in.ServerCertificateName), inputString(in.Path)
	default:
		return "", false
	}
	return resourceARN(m, kind, defaultPath(path), name), true
}
