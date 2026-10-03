package iam

import (
	"context"
	"strings"

	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) serviceLinkedAuthorizationResource(ctx context.Context, a *account, m awsctx.Metadata) (string, bool) {
	decoded, _ := awsapi.FromContext(ctx)
	switch in := decoded.Input.(type) {
	case *iamapi.CreateServiceLinkedRoleInput:
		template, err := s.serviceLinkedTemplate(m.Partition, inputString(in.AWSServiceName))
		if err != nil {
			return "*", true
		}
		name, err := serviceLinkedRoleName(template, inputString(in.CustomSuffix), in.CustomSuffix != nil)
		if err != nil {
			return "*", true
		}
		return resourceARN(m, "role", "/aws-service-role/"+template.ServiceName+"/", name), true
	case *iamapi.GetServiceLinkedRoleDeletionStatusInput:
		if job := a.serviceLinkedDeletions[inputString(in.DeletionTaskId)]; job != nil {
			return job.RoleARN, true
		}
		// Retaining the ARN in the job preserves resource authorization after
		// deletion. An unknown ID must not borrow another account's job.
		return "*", true
	default:
		return "", false
	}
}

func serviceLinkedAuthorizationContext(ctx context.Context) map[string][]string {
	in, ok := awsapi.Input[iamapi.CreateServiceLinkedRoleInput](ctx)
	if !ok {
		return nil
	}
	return map[string][]string{"iam:AWSServiceName": {inputString(in.AWSServiceName)}}
}

func protectRoleMutation(ctx context.Context, a *account) *awswire.Error {
	decoded, _ := awsapi.FromContext(ctx)
	var name string
	var updateDuration bool
	var serviceLinkedAllowed bool
	switch in := decoded.Input.(type) {
	case *iamapi.UpdateAssumeRolePolicyInput:
		name = inputString(in.RoleName)
	case *iamapi.PutRolePolicyInput:
		name = inputString(in.RoleName)
	case *iamapi.DeleteRolePolicyInput:
		name = inputString(in.RoleName)
	case *iamapi.AttachRolePolicyInput:
		name = inputString(in.RoleName)
	case *iamapi.DetachRolePolicyInput:
		name = inputString(in.RoleName)
	case *iamapi.PutRolePermissionsBoundaryInput:
		name = inputString(in.RoleName)
	case *iamapi.DeleteRolePermissionsBoundaryInput:
		name = inputString(in.RoleName)
	case *iamapi.DeleteRoleInput:
		name = inputString(in.RoleName)
	case *iamapi.AddRoleToInstanceProfileInput:
		name = inputString(in.RoleName)
	case *iamapi.RemoveRoleFromInstanceProfileInput:
		name = inputString(in.RoleName)
	case *iamapi.UpdateRoleInput:
		name, updateDuration = inputString(in.RoleName), in.MaxSessionDuration != nil
		serviceLinkedAllowed = !updateDuration
	case *iamapi.UpdateRoleDescriptionInput:
		name, serviceLinkedAllowed = inputString(in.RoleName), true
	case *iamapi.TagRoleInput:
		name, serviceLinkedAllowed = inputString(in.RoleName), true
	case *iamapi.UntagRoleInput:
		name, serviceLinkedAllowed = inputString(in.RoleName), true
	default:
		return nil
	}
	r := a.roles[strings.ToLower(name)]
	if r == nil {
		return nil
	}
	// Identity Center owns these roles without the Organizations exemptions
	// granted to service-linked roles. Only its trusted provisioning API may
	// mutate them; ownership, not a user-chosen name, establishes protection.
	if r.IdentityCenterInstanceARN != "" {
		return &awswire.Error{Code: "UnmodifiableEntity", StatusCode: 400, Message: "Cannot perform the operation on the protected role '" + r.RoleName + "' - this role is only modifiable by AWS"}
	}
	if r.ServiceLinkedService == "" || serviceLinkedAllowed {
		return nil
	}
	if updateDuration {
		return &awswire.Error{Code: "UnmodifiableEntity", StatusCode: 400, Message: r.RoleName + " is an AWS service linked role, max session duration cannot be changed."}
	}
	return &awswire.Error{Code: "UnmodifiableEntity", StatusCode: 400, Message: "Cannot perform the operation on the protected role '" + r.RoleName + "' - this role is only modifiable by AWS"}
}
