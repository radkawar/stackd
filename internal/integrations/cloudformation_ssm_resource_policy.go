package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/services/cloudformation"
	ssmowner "stackd/internal/services/ssm"
)

// cfnSSMResourcePolicy attaches one resource policy through the SSM owner.
// The stackd SSM owner supports parameter ARNs; other ARNs, including
// OpsItemGroup, remain explicit owner rejections.
//
// The SSM owner stores this incarnation's private claim on the policy in the
// same transaction that creates it. A retried create recovers exactly that
// policy; updates and deletes are rejected for policies the claim does not own.
type cfnSSMResourcePolicy struct{ commands StepFunctionsCommands }
type cfnSSMResourcePolicyProperties struct {
	ResourceArn string
	Policy      any
}

func (h cfnSSMResourcePolicy) decode(raw cloudformation.Properties) (cfnSSMResourcePolicyProperties, string, error) {
	var p cfnSSMResourcePolicyProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, "", err
	}
	if len(p.ResourceArn) < 20 || len(p.ResourceArn) > 2048 {
		return p, "", fmt.Errorf("ResourceArn must be 20 through 2048 characters")
	}
	var document string
	switch value := p.Policy.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return p, "", fmt.Errorf("policy must not be empty")
		}
		document = value
	case map[string]any:
		raw, err := json.Marshal(value)
		if err != nil {
			return p, "", err
		}
		document = string(raw)
	default:
		return p, "", fmt.Errorf("policy must be a JSON object or string")
	}
	return p, document, nil
}
func (h cfnSSMResourcePolicy) Validate(raw cloudformation.Properties) error {
	_, _, err := h.decode(raw)
	return err
}
func (h cfnSSMResourcePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnMessagingChanged(a, b, "ResourceArn"), nil
}
func cfnSSMResourcePolicyIdentifier(id string) (policy, arn string, err error) {
	policy, arn, found := strings.Cut(id, "|")
	if !found || policy == "" || arn == "" {
		return "", "", fmt.Errorf("resource policy identifier must be PolicyId|ResourceArn")
	}
	return policy, arn, nil
}
func (h cfnSSMResourcePolicy) result(policy, arn, hash string) cloudformation.ResourceResult {
	result := cfnMessagingResult(policy + "|" + arn)
	result.Attributes = map[string]any{"PolicyId": policy, "PolicyHash": hash}
	return result
}

// owned scopes stack commands to this resource incarnation. Cloud Control
// operates on existing policies without a stack claim.
func (h cfnSSMResourcePolicy) owned(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return ssmowner.WithCloudFormationResourcePolicyOwner(ctx, cfnMessagingMarker(r))
}

// policies lists the resource's policies; under a stack claim the owner
// returns only the policy this incarnation created.
func (h cfnSSMResourcePolicy) policies(ctx context.Context, arn string) (map[string]api.GetResourcePoliciesResponseEntry, error) {
	out := map[string]api.GetResourcePoliciesResponseEntry{}
	in := map[string]any{"ResourceArn": arn}
	for {
		page, err := cfnComputeCall[api.GetResourcePoliciesResponse](ctx, h.commands, "ssm", "GetResourcePolicies", in)
		if err != nil {
			return nil, err
		}
		for _, policy := range page.Policies {
			out[cfnComputeValue(policy.PolicyId)] = policy
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		in["NextToken"] = string(*page.NextToken)
	}
}
func (h cfnSSMResourcePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, document, err := h.decode(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.PutResourcePolicyResponse](h.owned(ctx, r), h.commands, "ssm", "PutResourcePolicy", map[string]any{"ResourceArn": p.ResourceArn, "Policy": document})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(cfnComputeValue(out.PolicyId), p.ResourceArn, cfnComputeValue(out.PolicyHash)), nil
}

// current resolves the stored policy visible to this request's claim.
func (h cfnSSMResourcePolicy) current(ctx context.Context, r cloudformation.ResourceRequest) (id, arn string, policy api.GetResourcePoliciesResponseEntry, err error) {
	if id, arn, err = cfnSSMResourcePolicyIdentifier(r.PhysicalID); err != nil {
		return
	}
	policies, err := h.policies(ctx, arn)
	if err != nil {
		return
	}
	policy, ok := policies[id]
	if !ok {
		err = cfnStorageNotFound("resource policy " + id + " does not exist for this resource")
	}
	return
}
func (h cfnSSMResourcePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate("AWS::SSM::ResourcePolicy", r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	result := cfnMessagingResult(r.PhysicalID)
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return result, err
	}
	if replace {
		return result, fmt.Errorf("resource policy update requires replacement")
	}
	_, document, err := h.decode(r.Properties)
	if err != nil {
		return result, err
	}
	ctx = h.owned(ctx, r)
	id, arn, policy, err := h.current(ctx, r)
	if err != nil {
		return result, err
	}
	out, err := cfnComputeCall[api.PutResourcePolicyResponse](ctx, h.commands, "ssm", "PutResourcePolicy", map[string]any{"ResourceArn": arn, "Policy": document, "PolicyId": id, "PolicyHash": cfnComputeValue(policy.PolicyHash)})
	if err != nil {
		return result, err
	}
	return h.result(id, arn, cfnComputeValue(out.PolicyHash)), nil
}
func (h cfnSSMResourcePolicy) delete(ctx context.Context, arn, id string, policy api.GetResourcePoliciesResponseEntry) error {
	err := cfnComputeRun(ctx, h.commands, "ssm", "DeleteResourcePolicy", map[string]any{"ResourceArn": arn, "PolicyId": id, "PolicyHash": cfnComputeValue(policy.PolicyHash)})
	return cfnStorageMissing(err, "ResourcePolicyNotFoundException", "ResourceNotFoundException")
}
func (h cfnSSMResourcePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = h.owned(ctx, r)
	if r.PhysicalID == "" && !r.CloudControl {
		// A create that did not publish its identifier may still have
		// committed; the owner reveals only this incarnation's policy.
		p, _, err := h.decode(r.Properties)
		if err != nil {
			return err
		}
		policies, err := h.policies(ctx, p.ResourceArn)
		if cfnMessagingMissing(err, "ResourceNotFoundException") {
			return nil
		}
		if err != nil {
			return err
		}
		for _, id := range cfnMessagingKeys(policies) {
			if err := h.delete(ctx, p.ResourceArn, id, policies[id]); err != nil && !cfnMessagingMissing(err, "NotFound") {
				return err
			}
		}
		return nil
	}
	id, arn, policy, err := h.current(ctx, r)
	if err == nil {
		err = h.delete(ctx, arn, id, policy)
	}
	err = cfnStorageMissing(err, "ResourceNotFoundException")
	if cfnMessagingMissing(err, "NotFound") && !r.CloudControl {
		return nil
	}
	return err
}
func (h cfnSSMResourcePolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	id, arn, policy, err := h.current(ctx, r)
	if err != nil {
		return nil, cfnStorageMissing(err, "ResourceNotFoundException")
	}
	return cfnSSMResourcePolicyProjection(id, arn, policy)
}
func cfnSSMResourcePolicyProjection(id, arn string, policy api.GetResourcePoliciesResponseEntry) (cloudformation.Properties, error) {
	var document map[string]any
	if err := cfnStorageJSON(cfnComputeValue(policy.Policy), &document); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"PolicyId": id, "ResourceArn": arn, "PolicyHash": cfnComputeValue(policy.PolicyHash), "Policy": document}, nil
}

// List enumerates policies on the account's parameters in this Region, the
// only resources the SSM owner can attach resource policies to.
func (h cfnSSMResourcePolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var out []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		page, err := cfnComputeCall[api.DescribeParametersOutput](ctx, h.commands, "ssm", "DescribeParameters", in)
		if err != nil {
			return nil, err
		}
		for _, row := range page.Parameters {
			arn := cfnComputeValue(row.ARN)
			if arn == "" {
				continue
			}
			policies, err := h.policies(ctx, arn)
			if err != nil {
				return nil, err
			}
			for _, id := range cfnMessagingKeys(policies) {
				p, err := cfnSSMResourcePolicyProjection(id, arn, policies[id])
				if err != nil {
					return nil, err
				}
				out = append(out, cloudformation.ResourceDescription{Identifier: id + "|" + arn, Properties: p})
			}
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		in["NextToken"] = string(*page.NextToken)
	}
}

var _ cloudformation.ResourceReader = cfnSSMResourcePolicy{}
