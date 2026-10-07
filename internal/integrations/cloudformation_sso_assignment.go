package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/ssoadmin"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sso-assignment.html
type cfnSSOAssignment struct{ commands StepFunctionsCommands }

var cfnSSOAssignmentKeys = []string{"InstanceArn", "TargetId", "TargetType", "PermissionSetArn", "PrincipalType", "PrincipalId"}

func (h cfnSSOAssignment) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, cfnSSOAssignmentKeys...); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, cfnSSOAssignmentKeys...); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, cfnSSOAssignmentKeys...); e != nil {
		return e
	}
	if p["TargetType"] != "AWS_ACCOUNT" {
		return fmt.Errorf("TargetType must be AWS_ACCOUNT")
	}
	if p["PrincipalType"] != "USER" && p["PrincipalType"] != "GROUP" {
		return fmt.Errorf("PrincipalType must be USER or GROUP")
	}
	return nil
}
func (h cfnSSOAssignment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, cfnSSOAssignmentKeys...), h.Validate(b)
}
func cfnSSOAssignmentID(p cloudformation.Properties) string {
	parts := make([]string, len(cfnSSOAssignmentKeys))
	for i, k := range cfnSSOAssignmentKeys {
		parts[i] = cfnComputeString(p, k)
	}
	return cfnOrgIdentityID(parts...)
}
func cfnSSOAssignmentProperties(id string) (cloudformation.Properties, error) {
	parts, e := cfnOrgIdentityParts(id, len(cfnSSOAssignmentKeys))
	if e != nil {
		return nil, e
	}
	p := cloudformation.Properties{}
	for i, k := range cfnSSOAssignmentKeys {
		p[k] = parts[i]
	}
	return p, nil
}
func (h cfnSSOAssignment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	out, e := cfnOrgIdentityCall[api.CreateAccountAssignmentOutput](cfnOrgIdentityContext(ctx, r), h.commands, "ssoadmin", "CreateAccountAssignment", cfnComputeCopy(r.Properties, cfnSSOAssignmentKeys...))
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	id := cfnSSOAssignmentID(r.Properties)
	result := cfnOrgIdentityResult(id, cloudformation.Properties{})
	if out.AccountAssignmentCreationStatus == nil || cfnComputeValue(out.AccountAssignmentCreationStatus.Status) != "SUCCEEDED" {
		return result, fmt.Errorf("assignment provisioning did not complete")
	}
	return result, nil
}
func (h cfnSSOAssignment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(cfnOrgIdentityContext(ctx, r), r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if cfnSSOAssignmentID(r.Properties) != r.PhysicalID {
		return cloudformation.ResourceResult{}, fmt.Errorf("assignment identity changes require replacement")
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnSSOAssignment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	p, e := cfnSSOAssignmentProperties(r.PhysicalID)
	if e != nil {
		return e
	}
	out, e := cfnOrgIdentityCall[api.DeleteAccountAssignmentOutput](cfnOrgIdentityContext(ctx, r), h.commands, "ssoadmin", "DeleteAccountAssignment", p)
	if cfnComputeMissing(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if out.AccountAssignmentDeletionStatus == nil || cfnComputeValue(out.AccountAssignmentDeletionStatus.Status) != "SUCCEEDED" {
		return fmt.Errorf("assignment deletion did not complete")
	}
	return nil
}
func (h cfnSSOAssignment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	p, e := cfnSSOAssignmentProperties(r.PhysicalID)
	if e != nil {
		return nil, e
	}
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListAccountAssignmentsOutput](ctx, h.commands, "ssoadmin", "ListAccountAssignments", map[string]any{"InstanceArn": p["InstanceArn"], "PermissionSetArn": p["PermissionSetArn"], "AccountId": p["TargetId"], "NextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.AccountAssignments {
			if cfnComputeValue(v.PrincipalType) == p["PrincipalType"] && cfnComputeValue(v.PrincipalId) == p["PrincipalId"] {
				return p, nil
			}
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Account assignment was not found", StatusCode: 400}
		}
	}
}
func (h cfnSSOAssignment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	permissions, e := (cfnSSOPermissionSet(h)).List(ctx, r)
	if e != nil {
		return nil, e
	}
	var rows []cloudformation.ResourceDescription
	for _, ps := range permissions {
		instance, arn := cfnComputeString(ps.Properties, "InstanceArn"), cfnComputeString(ps.Properties, "PermissionSetArn")
		accountNext := ""
		for {
			accounts, e := cfnOrgIdentityCall[api.ListAccountsForProvisionedPermissionSetOutput](ctx, h.commands, "ssoadmin", "ListAccountsForProvisionedPermissionSet", map[string]any{"InstanceArn": instance, "PermissionSetArn": arn, "NextToken": accountNext})
			if e != nil {
				return nil, e
			}
			for _, account := range accounts.AccountIds {
				next := ""
				for {
					out, e := cfnOrgIdentityCall[api.ListAccountAssignmentsOutput](ctx, h.commands, "ssoadmin", "ListAccountAssignments", map[string]any{"InstanceArn": instance, "PermissionSetArn": arn, "AccountId": string(account), "NextToken": next})
					if e != nil {
						return nil, e
					}
					for _, v := range out.AccountAssignments {
						p := cloudformation.Properties{"InstanceArn": instance, "PermissionSetArn": arn, "TargetType": "AWS_ACCOUNT", "TargetId": string(account), "PrincipalType": cfnComputeValue(v.PrincipalType), "PrincipalId": cfnComputeValue(v.PrincipalId)}
						rows = append(rows, cloudformation.ResourceDescription{Identifier: cfnSSOAssignmentID(p), Properties: p})
					}
					next = cfnComputeValue(out.NextToken)
					if next == "" {
						break
					}
				}
			}
			accountNext = cfnComputeValue(accounts.NextToken)
			if accountNext == "" {
				break
			}
		}
	}
	return rows, nil
}
