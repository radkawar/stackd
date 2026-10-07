package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/services/cloudformation"
)

// Account identity fields are not updateable; deletion defaults to Retain.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-organizations-account.html
type cfnOrganizationAccount struct{ commands StepFunctionsCommands }

func (h cfnOrganizationAccount) Validate(p cloudformation.Properties) error {
	if e := cfnOrganizationsValidate(p, []string{"AccountName", "Email"}, "AccountName", "Email", "RoleName", "ParentIds", "Tags"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "AccountName", "Email", "RoleName"); e != nil {
		return e
	}
	parents, e := cfnComputeStringList(p, "ParentIds")
	if e != nil {
		return e
	}
	if len(parents) > 1 {
		return fmt.Errorf("ParentIds accepts exactly one parent")
	}
	return nil
}
func (h cfnOrganizationAccount) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func (h cfnOrganizationAccount) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	input := cfnComputeCopy(r.Properties, "AccountName", "Email", "RoleName")
	input["Tags"] = cfnComputeTagList(cfnOrgIdentityTags(r))
	out, e := cfnOrgIdentityCall[api.CreateAccountOutput](cfnOrgIdentityClaim(ctx, r), h.commands, "organizations", "CreateAccount", input)
	if e != nil {
		admitted, recovery := h.RecoverCreation(ctx, r)
		if recovery == nil {
			return admitted, e
		}
		return cloudformation.ResourceResult{}, e
	}
	if out.CreateAccountStatus == nil || cfnComputeValue(out.CreateAccountStatus.AccountId) == "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("organizations did not reserve an account identity")
	}
	id := cfnComputeValue(out.CreateAccountStatus.AccountId)
	return cfnOrgIdentityResult(id, cloudformation.Properties{"AccountId": id}), nil
}

// RecoverCreation observes the atomically admitted private receipt, including
// its reserved identity while native provisioning remains in progress.
func (h cfnOrganizationAccount) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListCreateAccountStatusOutput](cfnOrgIdentityClaim(ctx, r), h.commands, "organizations", "ListCreateAccountStatus", map[string]any{"NextToken": next})
		if e != nil {
			return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
		}
		if len(out.CreateAccountStatuses) > 0 {
			id := cfnComputeValue(out.CreateAccountStatuses[0].AccountId)
			if id == "" {
				return cloudformation.ResourceResult{}, fmt.Errorf("owned account receipt has no reserved identity")
			}
			return cfnOrgIdentityResult(id, cloudformation.Properties{"AccountId": id}), nil
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("account was not created by this incarnation")
		}
	}
}
func (h cfnOrganizationAccount) status(ctx context.Context, r cloudformation.ResourceRequest) (*api.CreateAccountStatus, error) {
	ctx = cfnOrgIdentityClaim(ctx, r)
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListCreateAccountStatusOutput](ctx, h.commands, "organizations", "ListCreateAccountStatus", map[string]any{"NextToken": next})
		if e != nil {
			return nil, e
		}
		for i := range out.CreateAccountStatuses {
			v := &out.CreateAccountStatuses[i]
			if cfnComputeValue(v.AccountId) == r.PhysicalID {
				return v, nil
			}
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return nil, nil
		}
	}
}
func (h cfnOrganizationAccount) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	status, e := h.status(ctx, r)
	if e != nil {
		return false, e
	}
	if status != nil {
		switch cfnComputeValue(status.State) {
		case "IN_PROGRESS":
			return false, nil
		case "FAILED":
			return false, fmt.Errorf("account provisioning failed: %s", cfnComputeValue(status.FailureReason))
		case "SUCCEEDED":
		default:
			return false, fmt.Errorf("unknown account provisioning state")
		}
	}
	if _, e := cfnOrganizationsAccountTags(ctx, h.commands, r, r.PhysicalID); e != nil {
		return false, e
	}
	if e := h.parent(cfnOrgIdentityContext(ctx, r), r); e != nil {
		return false, e
	}
	return true, nil
}
func (h cfnOrganizationAccount) parent(ctx context.Context, r cloudformation.ResourceRequest) error {
	parents, e := cfnComputeStringList(r.Properties, "ParentIds")
	if e != nil {
		return e
	}
	desired := ""
	if len(parents) == 1 {
		desired = parents[0]
	} else {
		desired, e = cfnOrganizationsRoot(ctx, h.commands)
		if e != nil {
			return e
		}
	}
	current, e := cfnOrganizationsParent(ctx, h.commands, r.PhysicalID)
	if e != nil {
		return e
	}
	if current == desired {
		return nil
	}
	return cfnComputeRun(ctx, h.commands, "organizations", "MoveAccount", map[string]any{"AccountId": r.PhysicalID, "SourceParentId": current, "DestinationParentId": desired})
}
func (h cfnOrganizationAccount) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if cfnComputeChanged(r.Previous, r.Properties, "AccountName", "Email", "RoleName") {
		return cloudformation.ResourceResult{}, fmt.Errorf("AccountName, Email and RoleName updates are not supported")
	}
	ctx = cfnOrgIdentityContext(ctx, r)
	tags, e := cfnOrganizationsAccountTags(ctx, h.commands, r, r.PhysicalID)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if e = h.parent(ctx, r); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	e = cfnOrganizationsUpdateTags(ctx, h.commands, r, r.PhysicalID, tags, cfnOrgIdentityTags(r))
	result, re := cfnOrgIdentityRefreshResult(ctx, h, r)
	if e != nil {
		return result, e
	}
	return result, re
}
func (h cfnOrganizationAccount) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.DeletionPolicy == "" || r.DeletionPolicy == "Retain" {
		return nil
	}
	if r.PhysicalID == "" {
		return nil
	}
	ctx = cfnOrgIdentityContext(ctx, r)
	status, e := h.status(ctx, r)
	if e != nil {
		return e
	}
	if status != nil && cfnComputeValue(status.State) == "IN_PROGRESS" {
		return fmt.Errorf("account creation is in progress")
	}
	if status != nil && cfnComputeValue(status.State) == "FAILED" {
		return nil
	}
	_, e = cfnOrganizationsAccountTags(ctx, h.commands, r, r.PhysicalID)
	if cfnOrganizationsMissing(e) {
		return nil
	}
	if e != nil {
		return e
	}
	e = cfnComputeRun(ctx, h.commands, "organizations", "RemoveAccountFromOrganization", map[string]any{"AccountId": r.PhysicalID})
	if cfnOrganizationsMissing(e) {
		return nil
	}
	return e
}
func (h cfnOrganizationAccount) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, e := cfnOrgIdentityCall[api.DescribeAccountOutput](ctx, h.commands, "organizations", "DescribeAccount", map[string]any{"AccountId": r.PhysicalID})
	if e != nil {
		return nil, e
	}
	a := out.Account
	tags, e := cfnOrganizationsTags(ctx, h.commands, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	parent, e := cfnOrganizationsParent(ctx, h.commands, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	path, e := cfnOrganizationsPath(ctx, h.commands, parent)
	if e != nil {
		return nil, e
	}
	p := cloudformation.Properties{"AccountId": r.PhysicalID, "Arn": cfnComputeValue(a.Arn), "AccountName": cfnComputeValue(a.Name), "Email": cfnComputeValue(a.Email), "State": cfnComputeValue(a.State), "Status": cfnComputeValue(a.Status), "JoinedMethod": cfnComputeValue(a.JoinedMethod), "JoinedTimestamp": a.JoinedTimestamp, "ParentIds": []any{parent}, "Paths": []any{path}, "Tags": cfnOrgIdentityPublicTags(tags)}
	return p, nil
}
func (h cfnOrganizationAccount) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnOrganizationAccount) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListAccountsOutput](ctx, h.commands, "organizations", "ListAccounts", map[string]any{"NextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.Accounts {
			r.PhysicalID = cfnComputeValue(v.Id)
			p, e := h.Read(ctx, r)
			if e != nil {
				return nil, e
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
	}
}
