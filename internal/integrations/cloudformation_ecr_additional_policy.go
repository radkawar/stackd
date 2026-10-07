package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ecr"
)

func cfnECRSingletonContext(ctx context.Context, r cloudformation.ResourceRequest, kind string, enforce, release bool, rows map[string]string) context.Context {
	if r.CloudControl && enforce {
		return ctx
	}
	return ecr.WithCloudFormationOwnership(ctx, kind, cfnDeveloperClaim(r), enforce, release, rows)
}
func cfnECRSingletonResult(id string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"RegistryId": id}}
}
func cfnECRSingletonScope(r cloudformation.ResourceRequest) error {
	if r.PhysicalID != "" && r.PhysicalID != r.Scope.Account {
		return fmt.Errorf("registry identifier must belong to the current account")
	}
	return nil
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecr-registrypolicy.html
// Native bound policy principals remain authoritative through IAM recreation.
type cfnECRRegistryPolicy struct{ commands StepFunctionsCommands }

func (h cfnECRRegistryPolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "PolicyText"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "PolicyText"); err != nil {
		return err
	}
	_, err := cfnComputeDocument(p["PolicyText"])
	return err
}
func (h cfnECRRegistryPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func (h cfnECRRegistryPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnECRSingletonScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	rows := map[string]string{}
	ctx = cfnECRSingletonContext(ctx, r, "RegistryPolicy", false, false, rows)
	_, err := cfnComputeCall[api.GetRegistryPolicyOutput](ctx, h.commands, "ecr", "GetRegistryPolicy", map[string]any{})
	if err == nil {
		if rows[r.Scope.Account] != cfnDeveloperClaim(r) {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("registry policy belongs to another incarnation"))
		}
		return cfnECRSingletonResult(r.Scope.Account), nil
	}
	if !cfnMessagingMissing(err, "RegistryPolicyNotFoundException") {
		return cloudformation.ResourceResult{}, err
	}
	text, err := cfnComputeDocument(r.Properties["PolicyText"])
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.PutRegistryPolicyOutput](ctx, h.commands, "ecr", "PutRegistryPolicy", map[string]any{"policyText": text})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnECRSingletonResult(cfnComputeValue(out.RegistryId)), nil
}
func (h cfnECRRegistryPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnECRSingletonScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnECRSingletonContext(ctx, r, "RegistryPolicy", true, false, nil)
	text, err := cfnComputeDocument(r.Properties["PolicyText"])
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.PutRegistryPolicyOutput](ctx, h.commands, "ecr", "PutRegistryPolicy", map[string]any{"policyText": text})
	if err != nil {
		return cfnECRSingletonResult(r.PhysicalID), err
	}
	return cfnECRSingletonResult(cfnComputeValue(out.RegistryId)), nil
}
func (h cfnECRRegistryPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnECRSingletonScope(r); err != nil {
		return err
	}
	ctx = cfnECRSingletonContext(ctx, r, "RegistryPolicy", true, true, nil)
	err := cfnComputeRun(ctx, h.commands, "ecr", "DeleteRegistryPolicy", map[string]any{})
	if cfnMessagingMissing(err, "RegistryPolicyNotFoundException") {
		return nil
	}
	return err
}
func (h cfnECRRegistryPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnECRSingletonScope(r); err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetRegistryPolicyOutput](ctx, h.commands, "ecr", "GetRegistryPolicy", map[string]any{})
	if err != nil {
		return nil, err
	}
	var document any
	if err = json.Unmarshal([]byte(cfnComputeValue(out.PolicyText)), &document); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"RegistryId": cfnComputeValue(out.RegistryId), "PolicyText": document}, nil
}
func (h cfnECRRegistryPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	r.PhysicalID = r.Scope.Account
	p, err := h.Read(ctx, r)
	if cfnMessagingMissing(err, "RegistryPolicyNotFoundException") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []cloudformation.ResourceDescription{{Identifier: r.PhysicalID, Properties: p}}, nil
}
