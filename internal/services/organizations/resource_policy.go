package organizations

import (
	"errors"
	"net/http"
	"strings"

	iampolicy "stackd/iam/policy"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

func (s *Service) registerResourcePolicyOperations() {
	register(s, "PutResourcePolicy", (*operationState).putResourcePolicy)
	register(s, "DescribeResourcePolicy", func(s *operationState, r *http.Request, _ *api.DescribeResourcePolicyInput) (*api.DescribeResourcePolicyOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		if o.resourcePolicy.ID == "" {
			return nil, resourcePolicyMissing()
		}
		return &api.DescribeResourcePolicyOutput{ResourcePolicy: o.resourcePolicy.api()}, nil
	})
	register(s, "DeleteResourcePolicy", func(s *operationState, r *http.Request, _ *api.DeleteResourcePolicyInput) (*api.DeleteResourcePolicyOutput, *awswire.Error) {
		o, err := s.organizationFor(r, true)
		if err != nil {
			return nil, err
		}
		if o.resourcePolicy.ID == "" {
			return nil, resourcePolicyMissing()
		}
		delete(o.tags, o.resourcePolicy.ID)
		o.resourcePolicy = ResourcePolicyRecord{}
		return &api.DeleteResourcePolicyOutput{}, nil
	})
}

func (s *operationState) putResourcePolicy(r *http.Request, in *api.PutResourcePolicyInput) (*api.PutResourcePolicyOutput, *awswire.Error) {
	o, err := s.organizationFor(r, true)
	if err != nil {
		return nil, err
	}
	if o.resourcePolicy.ID != "" && len(in.Tags) != 0 {
		return nil, failure("ConstraintViolationException", "UPDATE_EXISTING_RESOURCE_POLICY_WITH_TAGS_NOT_SUPPORTED: Adding tags when updating a resource policy is not supported.")
	}
	actions := map[string]bool{}
	model, _ := awscatalog.LookupService("organizations")
	for _, operation := range model.Operations() {
		actions["organizations:"+string(operation.Name)] = delegationActionAllowed(string(operation.Name))
	}
	doc, canonical, parseErr := iampolicy.ParseDelegation([]byte(*in.Content), s.partition, actions)
	if parseErr != nil {
		var unsupported *iampolicy.UnsupportedDelegationAction
		if errors.As(parseErr, &unsupported) {
			return nil, failure("InvalidInputException", "UNSUPPORTED_ACTION_IN_RESOURCE_POLICY: "+unsupported.Action+" is not supported in a delegation policy.")
		}
		return nil, invalidResourcePolicy()
	}
	for _, principal := range doc.AWSPrincipals() {
		if principal == "*" {
			continue
		}
		account := principal
		if strings.HasPrefix(account, "arn:") {
			account = strings.SplitN(account, ":", 6)[4]
		}
		if _, member := o.accounts[account]; !member {
			return nil, invalidResourcePolicy()
		}
	}
	if o.resourcePolicy.ID == "" {
		tags, err := mergeTags(nil, in.Tags)
		if err != nil {
			return nil, err
		}
		id := s.createdResourceID
		o.resourcePolicy = ResourcePolicyRecord{ID: id, ARN: o.arn(s.partition, "resourcepolicy", id)}
		o.tags[id] = tags
	}
	o.resourcePolicy.Content = string(canonical)
	return &api.PutResourcePolicyOutput{ResourcePolicy: o.resourcePolicy.api()}, nil
}

func (v ResourcePolicyRecord) api() *api.ResourcePolicy {
	return &api.ResourcePolicy{Content: new(api.ResourcePolicyContent(v.Content)),
		ResourcePolicySummary: &api.ResourcePolicySummary{Id: new(api.ResourcePolicyId(v.ID)), Arn: new(api.ResourcePolicyArn(v.ARN))}}
}

func resourcePolicyMissing() *awswire.Error {
	return failure("ResourcePolicyNotFoundException", "No resource-based policy found.")
}
func invalidResourcePolicy() *awswire.Error {
	return failure("InvalidInputException", "INVALID_RESOURCE_POLICY_JSON: The delegation policy is invalid.")
}

// Organizations permits a defined set of reads plus policy management.
// https://docs.aws.amazon.com/organizations/latest/userguide/orgs-policy-delegate.html
func delegationActionAllowed(action string) bool {
	if delegatedReadAllowed(action) {
		return true
	}
	switch action {
	// Newer reads are accepted by AWS even though the delegation guide's
	// action list omits them; see organizations_delegation_writes.json.
	case "DescribeResponsibilityTransfer", "ListAccountsWithInvalidEffectivePolicy", "ListInboundResponsibilityTransfers", "ListOutboundResponsibilityTransfers":
		return true
	case "AttachPolicy", "CreatePolicy", "DeletePolicy", "DetachPolicy", "DisablePolicyType", "EnablePolicyType", "TagResource", "UntagResource", "UpdatePolicy":
		return true
	default:
		return false
	}
}
