package organizations

import (
	"maps"
	"net/http"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Resource requirements follow the AWS Organizations authorization reference:
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_organizations.html
func (s *operationState) authorizationPlan(r *http.Request, action string, input any) ([]authorization.Request, *awswire.Error) {
	m := awsctx.FromContext(r.Context())
	if selector, ok := input.(interface{ ResourceHandshakeID() *string }); ok {
		return s.handshakePermission(r, action, inputString(selector.ResourceHandshakeID()))
	}
	o := s.orgs[s.memberships[m.AccountID]]
	conditions := make(map[string][]string)
	if selected, ok := input.(interface{ RequestServicePrincipal() *string }); ok {
		if principal := inputString(selected.RequestServicePrincipal()); principal != "" {
			conditions["organizations:ServicePrincipal"] = []string{principal}
		}
	}
	kind := ""
	if selected, ok := input.(interface{ RequestPolicyType() *string }); ok {
		kind = inputString(selected.RequestPolicyType())
	}
	if selected, ok := input.(interface{ ResourcePolicyID() *string }); ok && o != nil {
		if p, ok := o.policies[inputString(selected.ResourcePolicyID())]; ok {
			kind = p.PolicySummary.Type
		}
	}
	if kind != "" {
		conditions["organizations:PolicyType"] = []string{kind}
	}
	var tags api.Tags
	if selected, ok := input.(interface{ RequestTags() api.Tags }); ok {
		tags = selected.RequestTags()
	}
	for _, tag := range tags {
		key, value := string(*tag.Key), string(*tag.Value)
		conditions["aws:RequestTag/"+key] = []string{value}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
	}
	if selected, ok := input.(interface{ RequestTagKeys() api.TagKeys }); ok {
		for _, key := range selected.RequestTagKeys() {
			conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(key))
		}
	}
	var ids []string
	var createdARN string
	switch action {
	case "EnableAllFeatures", "InviteAccountToOrganization", "ListHandshakesForAccount", "ListHandshakesForOrganization", "DescribeResourcePolicy", "DeleteResourcePolicy", "CreateOrganization", "DeleteOrganization", "DescribeOrganization", "CreateAccount", "DescribeCreateAccountStatus", "ListCreateAccountStatus", "ListAccounts", "LeaveOrganization", "ListRoots", "EnableAWSServiceAccess", "DisableAWSServiceAccess", "ListAWSServiceAccessForOrganization", "ListDelegatedAdministrators", "ListPolicies":
		ids = []string{"*"}
	case "DescribeAccount", "ListEffectivePolicyValidationErrors", "CloseAccount", "RemoveAccountFromOrganization", "ListDelegatedServicesForAccount", "RegisterDelegatedAdministrator", "DeregisterDelegatedAdministrator":
		ids = []string{inputString(input.(interface{ ResourceAccountID() *string }).ResourceAccountID())}
	case "CreateOrganizationalUnit", "ListAccountsForParent", "ListChildren", "ListOrganizationalUnitsForParent":
		ids = []string{inputString(input.(interface{ ResourceParentID() *string }).ResourceParentID())}
	case "DescribeOrganizationalUnit", "UpdateOrganizationalUnit", "DeleteOrganizationalUnit":
		ids = []string{inputString(input.(interface{ ResourceUnitID() *string }).ResourceUnitID())}
	case "ListParents":
		ids = []string{inputString(input.(interface{ ResourceChildID() *string }).ResourceChildID())}
	case "EnablePolicyType", "DisablePolicyType":
		ids = []string{inputString(input.(interface{ ResourceRootID() *string }).ResourceRootID())}
	case "DescribePolicy", "UpdatePolicy", "DeletePolicy", "ListTargetsForPolicy":
		ids = []string{inputString(input.(interface{ ResourcePolicyID() *string }).ResourcePolicyID())}
	case "AttachPolicy", "DetachPolicy":
		ids = []string{inputString(input.(interface{ ResourcePolicyID() *string }).ResourcePolicyID()), inputString(input.(interface{ ResourceTargetID() *string }).ResourceTargetID())}
	case "DescribeEffectivePolicy":
		id := inputString(input.(interface{ ResourceTargetID() *string }).ResourceTargetID())
		if id == "" {
			id = m.AccountID
		}
		ids = []string{id}
	case "ListPoliciesForTarget":
		ids = []string{inputString(input.(interface{ ResourceTargetID() *string }).ResourceTargetID())}
	case "MoveAccount":
		ids = []string{inputString(input.(interface{ ResourceAccountID() *string }).ResourceAccountID()), inputString(input.(interface{ ResourceSourceParentID() *string }).ResourceSourceParentID()), inputString(input.(interface{ ResourceDestinationParentID() *string }).ResourceDestinationParentID())}
	case "TagResource", "UntagResource", "ListTagsForResource":
		ids = []string{inputString(input.(interface{ ResourceID() *string }).ResourceID())}
	case "PutResourcePolicy":
		if o == nil {
			ids = []string{"*"}
			break
		}
		if o.resourcePolicy.ID != "" {
			ids = []string{o.resourcePolicy.ID}
			break
		}
		s.createdResourceID = identifier("rp-", 4)
		createdARN = o.arn(m.Partition, "resourcepolicy", s.createdResourceID)
		ids = []string{createdARN}
	case "CreatePolicy":
		if o == nil {
			ids = []string{"*"}
			break
		}
		s.createdResourceID = identifier("p-", 4)
		createdARN = o.arn(m.Partition, "policy", strings.ToLower(kind)+"/"+s.createdResourceID)
		ids = []string{createdARN}
	default:
		return nil, failure("AccessDeniedException", "This operation has no authorization contract.")
	}
	plan := make([]authorization.Request, 0, len(ids)+1)
	for _, id := range ids {
		plan = append(plan, organizationPermission(o, m.Partition, m.AccountID, action, id, conditions))
	}
	if o != nil && action == "CreateOrganizationalUnit" {
		s.createdResourceID = identifier("ou-"+strings.TrimPrefix(o.root.ID, "r-")+"-", 4)
		createdARN = o.arn(m.Partition, "ou", s.createdResourceID)
	}
	if o != nil && action == "CreateAccount" {
		s.createdResourceID, _ = s.nextAccountID()
		createdARN = o.arn(m.Partition, "account", s.createdResourceID)
		for _, job := range o.creations {
			if cloudFormationClaim(r) != "" && job.CloudFormationOwner == cloudFormationClaim(r) && job.RequestRegion == m.Region {
				createdARN = o.arn(m.Partition, "account", job.AccountID)
				break
			}
		}
	}
	if action == "DescribeEffectivePolicy" && o != nil && ids[0] == m.AccountID {
		plan[0].ResourceAccountGrant = true
	}
	if action == "ListHandshakesForAccount" && o != nil && o.organization.MasterAccountID != m.AccountID {
		plan[0].ResourceAccountGrant = true
	}
	if action == "InviteAccountToOrganization" && o != nil && len(tags) > 0 {
		in := input.(*api.InviteAccountToOrganizationInput)
		id := s.invitationTarget(inputString(in.Target.Type), inputString(in.Target.Id))
		createdARN = "*"
		if id != "" {
			createdARN = o.arn(m.Partition, "account", id)
		}
	}
	if createdARN != "" && len(tags) > 0 {
		plan = append(plan, organizationPermission(o, m.Partition, m.AccountID, "TagResource", createdARN, conditions))
	}
	return plan, nil
}

func organizationPermission(o *orgState, partition, accountID, action, id string, conditions map[string][]string) authorization.Request {
	arn, tags, policyType := organizationResource(o, partition, id)
	context := maps.Clone(conditions)
	if context == nil {
		context = make(map[string][]string)
	}
	for k, v := range tags {
		context["aws:ResourceTag/"+k] = []string{v}
	}
	if policyType != "" {
		context["organizations:PolicyType"] = []string{policyType}
	}
	request := authorization.Request{Action: "organizations:" + action, ResourceARN: arn, Context: context}
	if o == nil {
		return request
	}
	management := o.organization.MasterAccountID == accountID
	read := delegatedReadAllowed(action)
	awsOwned := strings.Contains(arn, ":organizations::aws:")
	// Global organization reads, delegation deletion and AWS's built-in policy
	// ARN alias resolve to the current management account.
	if (read || action == "DeleteResourcePolicy") && arn == "*" || awsOwned {
		request.ResourceAccountID = o.organization.MasterAccountID
	}
	if management {
		// Management-account access comes from IAM. The organization's
		// delegation policy governs its members.
		return request
	}
	// Membership grants DescribeOrganization; registered service administrators
	// also receive the documented reads. These grants do not override a deny in
	// the organization's delegation policy.
	request.ResourceAccountGrant = action == "DescribeOrganization" ||
		o.accounts[accountID].State == "ACTIVE" && len(o.delegates[accountID]) > 0 && read
	if delegationActionAllowed(action) {
		request.ResourcePolicies = []authorization.BoundPolicy{{Document: o.resourcePolicy.Content}}
	}
	return request
}

func organizationResource(o *orgState, partition, id string) (string, map[string]string, string) {
	if id == "*" || o == nil {
		return "*", nil, ""
	}
	if strings.HasPrefix(id, "arn:") {
		return id, nil, ""
	}
	if o.resourcePolicy.ID != "" && id == o.resourcePolicy.ID {
		return o.resourcePolicy.ARN, o.tags[id], ""
	}
	if id == o.root.ID {
		return o.root.ARN, o.tags[id], ""
	}
	if a, ok := o.accounts[id]; ok {
		return a.ARN, o.tags[id], ""
	}
	if u, ok := o.units[id]; ok {
		return u.ARN, o.tags[id], ""
	}
	if p, ok := o.policies[id]; ok {
		return p.PolicySummary.ARN, o.tags[id], p.PolicySummary.Type
	}
	// Missing identifiers are still authorized before the business operation
	// returns its modeled not-found error, without disclosing resource existence.
	resource := "account"
	if strings.HasPrefix(id, "ou-") {
		resource = "ou"
	}
	if strings.HasPrefix(id, "r-") {
		resource = "root"
	}
	if strings.HasPrefix(id, "p-") {
		resource = "policy"
	}
	if strings.HasPrefix(id, "rp-") {
		resource = "resourcepolicy"
	}
	return o.arn(partition, resource, id), nil, ""
}

func delegatedReadAllowed(action string) bool {
	switch action {
	case "DescribeAccount", "DescribeCreateAccountStatus", "DescribeEffectivePolicy", "ListEffectivePolicyValidationErrors",
		"DescribeHandshake", "DescribeOrganization", "DescribeOrganizationalUnit",
		"DescribePolicy", "DescribeResourcePolicy", "ListAccounts", "ListAccountsForParent",
		"ListAWSServiceAccessForOrganization", "ListChildren", "ListCreateAccountStatus",
		"ListDelegatedAdministrators", "ListDelegatedServicesForAccount",
		"ListHandshakesForAccount", "ListHandshakesForOrganization",
		"ListOrganizationalUnitsForParent", "ListParents", "ListPolicies",
		"ListPoliciesForTarget", "ListRoots", "ListTagsForResource", "ListTargetsForPolicy":
		return true
	default:
		return false
	}
}
