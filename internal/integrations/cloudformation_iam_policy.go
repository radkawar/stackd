package integrations

import (
	"context"
	"fmt"
	"slices"
	"stackd/internal/services/cloudformation"
	iamowner "stackd/internal/services/iam"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-policy.html
// IAM embedded policies own the claims, including cross-user/group/role aggregates.
type cfnIAMPolicy struct{ commands StepFunctionsCommands }

func cfnIAMPolicyOwner(r cloudformation.ResourceRequest) string {
	return r.Type + "#" + cfnComputeHash(r.StackID+"/"+r.LogicalID+"/"+r.Token)
}
func (h cfnIAMPolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "PolicyName", "PolicyDocument", "Roles", "Users", "Groups"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "PolicyName", "PolicyDocument"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "PolicyName"); err != nil {
		return err
	}
	if _, err := cfnComputeDocument(p["PolicyDocument"]); err != nil {
		return err
	}
	count := 0
	for _, key := range []string{"Roles", "Users", "Groups"} {
		list, err := cfnComputeStringList(p, key)
		if err != nil {
			return err
		}
		count += len(list)
	}
	if count == 0 {
		return fmt.Errorf("policy requires at least one Role, User or Group")
	}
	return nil
}
func (h cfnIAMPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func cfnIAMPolicyID(r cloudformation.ResourceRequest) string {
	if r.CloudControl && r.PhysicalID != "" {
		return r.PhysicalID
	}
	return cfnIAMPolicyOwner(r)
}
func cfnIAMAggregateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return iamowner.WithCloudFormationContext(ctx, iamowner.CloudFormationContext{Owner: cfnIAMPolicyID(r)})
}
func (h cfnIAMPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "PolicyName")
	document, _ := cfnComputeDocument(r.Properties["PolicyDocument"])
	id := cfnIAMPolicyID(r)
	result := cloudformation.ResourceResult{PhysicalID: id, Ref: name, Attributes: map[string]any{"Id": id}}
	admitted := false
	for key, kind := range map[string]string{"Roles": "Role", "Users": "User", "Groups": "Group"} {
		targets, _ := cfnComputeStringList(r.Properties, key)
		for _, target := range targets {
			if err := cfnComputeRun(cfnIAMAggregateContext(ctx, r), h.commands, "iam", "Put"+kind+"Policy", cfnIAMPolicyInputs(kind, target, name, document)); err != nil {
				if admitted {
					return result, err
				}
				return cfnIAMCreationFailure(ctx, r, h, err)
			}
			admitted = true
		}
	}
	return result, nil
}
func (h cfnIAMPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	before, err := h.List(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	exists := false
	for _, row := range before {
		if row.Identifier == cfnIAMPolicyID(r) {
			exists = true
			break
		}
	}
	if !exists {
		return cloudformation.ResourceResult{}, cfnIAMNotFound()
	}
	result, err := h.Create(ctx, r)
	if err != nil {
		return result, err
	}
	name := cfnComputeString(r.Properties, "PolicyName")
	for _, row := range before {
		if row.Identifier != cfnIAMPolicyID(r) {
			continue
		}
		oldName := cfnComputeString(row.Properties, "PolicyName")
		for key, kind := range map[string]string{"Roles": "Role", "Users": "User", "Groups": "Group"} {
			old, _ := row.Properties[key].([]string)
			desired, _ := cfnComputeStringList(r.Properties, key)
			for _, target := range old {
				if name != oldName || !slices.Contains(desired, target) {
					if err := cfnComputeAbsent(cfnComputeRun(cfnIAMAggregateContext(ctx, r), h.commands, "iam", "Delete"+kind+"Policy", cfnIAMPolicyInputs(kind, target, oldName, ""))); err != nil {
						return result, err
					}
				}
			}
		}
	}
	return result, nil
}
func (h cfnIAMPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	rows, err := h.List(ctx, r)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Identifier != cfnIAMPolicyID(r) {
			continue
		}
		name := cfnComputeString(row.Properties, "PolicyName")
		for key, kind := range map[string]string{"Roles": "Role", "Users": "User", "Groups": "Group"} {
			targets, _ := row.Properties[key].([]string)
			for _, target := range targets {
				if err := cfnComputeAbsent(cfnComputeRun(cfnIAMAggregateContext(ctx, r), h.commands, "iam", "Delete"+kind+"Policy", cfnIAMPolicyInputs(kind, target, name, ""))); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (h cfnIAMPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	rows, err := h.List(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Identifier == cfnIAMPolicyID(r) {
			return row.Properties, nil
		}
	}
	return nil, cfnIAMNotFound()
}
func (h cfnIAMPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	models := map[string]cloudformation.Properties{}
	var result []cloudformation.ResourceDescription
	for key, kind := range map[string]string{"Roles": "Role", "Users": "User", "Groups": "Group"} {
		targets, err := cfnIAMIdentityNames(ctx, h.commands, kind)
		if err != nil {
			return nil, err
		}
		for _, target := range targets {
			in := map[string]any{kind + "Name": target}
			for {
				owners := map[string]string{}
				owner := iamowner.CloudFormationContext{Owner: cfnIAMPolicyID(r), Direct: true, InlineOwners: &owners}
				listed, marker, err := cfnIAMListInline(iamowner.WithCloudFormationContext(ctx, owner), h.commands, kind, in)
				if err != nil {
					return nil, err
				}
				for _, policy := range listed {
					name := string(policy)
					id := owners[name]
					if !strings.HasPrefix(id, "AWS::IAM::Policy#") || (!r.CloudControl && id != cfnIAMPolicyID(r)) {
						continue
					}
					doc, err := cfnIAMGetInline(iamowner.WithCloudFormationContext(ctx, iamowner.CloudFormationContext{Owner: id}), h.commands, kind, cfnIAMPolicyInputs(kind, target, name, ""))
					if err != nil {
						return nil, err
					}
					modelKey := id + "/" + name
					p := models[modelKey]
					if p == nil {
						p = cloudformation.Properties{"Id": id, "PolicyName": name, "PolicyDocument": cfnIAMDocument(doc), "Roles": []string{}, "Users": []string{}, "Groups": []string{}}
						models[modelKey] = p
					}
					p[key] = append(p[key].([]string), target)
				}
				if marker == "" {
					break
				}
				in["Marker"] = marker
			}
		}
	}
	for _, p := range models {
		result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeString(p, "Id"), Properties: p})
	}
	return result, nil
}
