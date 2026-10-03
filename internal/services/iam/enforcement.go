package iam

import (
	"context"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) authorizeOperation(ctx context.Context, authorizer authorization.Authorizer, a *account, m awsctx.Metadata) *awswire.Error {
	decoded, _ := awsapi.FromContext(ctx)
	action := string(decoded.Operation.Name)
	if action == "AcquireRole" {
		// The acquisition handler owns its template-read and current-state
		// dependent permission plan in this same transaction.
		return nil
	}
	policyARN := ""
	if in, ok := decoded.Input.(interface{ PolicyARN() *iamapi.ArnType }); ok {
		policyARN = inputString(in.PolicyARN())
	}
	if policyARN != "" {
		parts := strings.SplitN(policyARN, ":", 6)
		if len(parts) == 6 && parts[0] == "arn" && parts[1] != m.Partition {
			return invalid("Invalid ARN partition")
		}
	}
	resource, tags, boundary, resourceErr := s.authorizationResource(ctx, a, m)
	if resourceErr != nil {
		return resourceErr
	}
	if in, ok := decoded.Input.(interface{ PermissionsBoundaryARN() *iamapi.ArnType }); ok && in.PermissionsBoundaryARN() != nil {
		boundary = inputString(in.PermissionsBoundaryARN())
	}
	condition := identityResourceConditions(tags, boundary)
	propertyConditions, propertyErr := accountPropertyConditions(ctx, action)
	if propertyErr != nil {
		return propertyErr
	}
	for key, values := range propertyConditions {
		condition[key] = values
	}
	for key, values := range serviceCredentialAuthorizationContext(ctx, a) {
		condition[key] = values
	}
	for key, values := range serviceLinkedAuthorizationContext(ctx) {
		condition[key] = values
	}
	if policyARN != "" {
		condition["iam:PolicyARN"] = []string{policyARN}
	}
	if in, ok := decoded.Input.(interface {
		OrganizationsPolicyID() *iamapi.OrganizationsPolicyIdType
	}); ok && in.OrganizationsPolicyID() != nil {
		condition["iam:OrganizationsPolicyId"] = []string{inputString(in.OrganizationsPolicyID())}
	}
	hasTags := requestTagConditions(decoded.Input, condition)
	request := authorization.Request{Action: "iam:" + action, ResourceARN: resource, Context: condition, EvaluationTime: &a.currentTime}
	owner, ownerErr := awsManagedResourceAccount(m.Partition, resource)
	if ownerErr != nil {
		return ownerErr
	}
	request.ResourceAccountID = owner
	if err := filterActionConditions(request.Action, condition); err != nil {
		return err
	}
	if err := authorizer.Authorize(ctx, request); err != nil {
		return err
	}
	if hasTags && (action == "CreateUser" || action == "CreateRole" || action == "CreatePolicy" || action == "CreateVirtualMFADevice" || action == "CreateInstanceProfile" || action == "CreateOpenIDConnectProvider" || action == "CreateSAMLProvider" || action == "UploadServerCertificate") {
		request.Action = "iam:Tag" + strings.TrimPrefix(action, "Create")
		if action == "UploadServerCertificate" {
			request.Action = "iam:TagServerCertificate"
		}
		if action == "CreateVirtualMFADevice" {
			request.Action = "iam:TagMFADevice"
		}
		if err := filterActionConditions(request.Action, condition); err != nil {
			return err
		}
		if err := authorizer.Authorize(ctx, request); err != nil {
			return err
		}
	}
	if err := protectRoleMutation(ctx, a); err != nil {
		return err
	}
	return authorizeInstanceProfileDependencies(ctx, authorizer, a, m)
}

func identityResourceConditions(tags []tag, boundary string) map[string][]string {
	conditions := make(map[string][]string)
	for _, tag := range tags {
		key := strings.ToLower(tag.Key)
		conditions["aws:resourcetag/"+key] = append(conditions["aws:resourcetag/"+key], tag.Value)
		conditions["iam:resourcetag/"+key] = append(conditions["iam:resourcetag/"+key], tag.Value)
	}
	if boundary != "" {
		conditions["iam:PermissionsBoundary"] = []string{boundary}
	}
	return conditions
}

func defaultPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
func boundaryARN(boundary *boundary) string {
	if boundary != nil {
		return boundary.PermissionsBoundaryArn
	}
	return ""
}
