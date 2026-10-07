package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/ssoadmin"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sso-permissionset.html
type cfnSSOPermissionSet struct{ commands StepFunctionsCommands }

func (h cfnSSOPermissionSet) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "Name", "InstanceArn", "Description", "SessionDuration", "RelayStateType", "ManagedPolicies", "InlinePolicy", "Tags", "CustomerManagedPolicyReferences", "PermissionsBoundary"); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "Name", "InstanceArn"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "Name", "InstanceArn", "Description", "SessionDuration", "RelayStateType"); e != nil {
		return e
	}
	if _, e := cfnComputeStringList(p, "ManagedPolicies"); e != nil {
		return e
	}
	if p["InlinePolicy"] != nil {
		if _, e := cfnComputeDocument(p["InlinePolicy"]); e != nil {
			return e
		}
	}
	if _, e := cfnSSOReferences(p["CustomerManagedPolicyReferences"]); e != nil {
		return e
	}
	if p["PermissionsBoundary"] != nil {
		b, ok := cfnComputeObject(p["PermissionsBoundary"])
		if !ok {
			return fmt.Errorf("PermissionsBoundary must be an object")
		}
		if e := cfnComputeProperties(b, "ManagedPolicyArn", "CustomerManagedPolicyReference"); e != nil {
			return e
		}
		if (b["ManagedPolicyArn"] == nil) == (b["CustomerManagedPolicyReference"] == nil) {
			return fmt.Errorf("PermissionsBoundary requires exactly one policy")
		}
		if e := cfnComputeStrings(b, "ManagedPolicyArn"); e != nil {
			return e
		}
		if b["CustomerManagedPolicyReference"] != nil {
			if _, e := cfnSSOReference(b["CustomerManagedPolicyReference"]); e != nil {
				return e
			}
		}
	}
	_, e := cfnComputeTags(p)
	return e
}
func cfnSSOReference(raw any) (map[string]any, error) {
	p, ok := cfnComputeObject(raw)
	if !ok {
		return nil, fmt.Errorf("policy reference must be an object")
	}
	if e := cfnComputeProperties(p, "Name", "Path"); e != nil {
		return nil, e
	}
	if e := cfnComputeRequired(p, "Name"); e != nil {
		return nil, e
	}
	if e := cfnComputeStrings(p, "Name", "Path"); e != nil {
		return nil, e
	}
	return map[string]any{"Name": p["Name"], "Path": cfnComputeDefault(p, "Path", "/")}, nil
}
func cfnSSOReferences(raw any) ([]map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("CustomerManagedPolicyReferences must be a list")
	}
	var out []map[string]any
	for _, v := range list {
		p, e := cfnSSOReference(v)
		if e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, nil
}
func (h cfnSSOPermissionSet) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "InstanceArn"), h.Validate(b)
}

// Permission sets carry a private incarnation claim. Native same-name sets and
// public tags are never adopted; Cloud Control direct mutations remain IAM-only.
func (h cfnSSOPermissionSet) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	instance := cfnComputeString(r.Properties, "InstanceArn")
	owned := cfnOrgIdentityClaim(ctx, r)
	input := cfnComputeCopy(r.Properties, "Name", "InstanceArn", "Description", "SessionDuration")
	if r.Properties["RelayStateType"] != nil {
		input["RelayState"] = r.Properties["RelayStateType"]
	}
	input["Tags"] = cfnComputeTagList(cfnOrgIdentityTags(r))
	out, e := cfnOrgIdentityCall[api.CreatePermissionSetOutput](owned, h.commands, "ssoadmin", "CreatePermissionSet", input)
	if cfnMessagingMissing(e, "ConflictException") {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, e)
	}
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	arn := cfnComputeValue(out.PermissionSet.PermissionSetArn)
	r.PhysicalID = cfnOrgIdentityID(arn, instance)
	result := cfnOrgIdentityResult(r.PhysicalID, cloudformation.Properties{"PermissionSetArn": arn})
	return result, h.configure(owned, r)
}

// RecoverCreation observes only the permission set committed under this exact incarnation.
func (h cfnSSOPermissionSet) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	instance := cfnComputeString(r.Properties, "InstanceArn")
	arns, e := h.arns(cfnOrgIdentityClaim(ctx, r), instance)
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	if len(arns) == 0 {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("permission set was not created by this incarnation")
	}
	id := cfnOrgIdentityID(arns[0], instance)
	return cfnOrgIdentityResult(id, cloudformation.Properties{"PermissionSetArn": arns[0]}), nil
}
func (h cfnSSOPermissionSet) configure(ctx context.Context, r cloudformation.ResourceRequest) error {
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return e
	}
	base := map[string]any{"InstanceArn": parts[1], "PermissionSetArn": parts[0]}
	current, e := h.Read(ctx, r)
	if e != nil {
		return e
	}
	managed, e := cfnComputeStringList(r.Properties, "ManagedPolicies")
	if e != nil {
		return e
	}
	old, e := cfnComputeStringList(current, "ManagedPolicies")
	if e != nil {
		return e
	}
	for _, arn := range old {
		if !slices.Contains(managed, arn) {
			in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
			in["ManagedPolicyArn"] = arn
			if e := cfnComputeRun(ctx, h.commands, "ssoadmin", "DetachManagedPolicyFromPermissionSet", in); e != nil {
				return e
			}
		}
	}
	for _, arn := range managed {
		if !slices.Contains(old, arn) {
			in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
			in["ManagedPolicyArn"] = arn
			if e := cfnComputeRun(ctx, h.commands, "ssoadmin", "AttachManagedPolicyToPermissionSet", in); e != nil {
				return e
			}
		}
	}
	refs, e := cfnSSOReferences(r.Properties["CustomerManagedPolicyReferences"])
	if e != nil {
		return e
	}
	oldRefs, e := cfnSSOReferences(current["CustomerManagedPolicyReferences"])
	if e != nil {
		return e
	}
	has := func(list []map[string]any, p map[string]any) bool {
		for _, v := range list {
			if v["Name"] == p["Name"] && v["Path"] == p["Path"] {
				return true
			}
		}
		return false
	}
	for _, ref := range oldRefs {
		if !has(refs, ref) {
			in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
			in["CustomerManagedPolicyReference"] = ref
			if e := cfnComputeRun(ctx, h.commands, "ssoadmin", "DetachCustomerManagedPolicyReferenceFromPermissionSet", in); e != nil {
				return e
			}
		}
	}
	for _, ref := range refs {
		if !has(oldRefs, ref) {
			in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
			in["CustomerManagedPolicyReference"] = ref
			if e := cfnComputeRun(ctx, h.commands, "ssoadmin", "AttachCustomerManagedPolicyReferenceToPermissionSet", in); e != nil {
				return e
			}
		}
	}
	if raw := r.Properties["InlinePolicy"]; raw != nil {
		doc, e := cfnComputeDocument(raw)
		if e != nil {
			return e
		}
		in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
		in["InlinePolicy"] = doc
		if e := cfnComputeRun(ctx, h.commands, "ssoadmin", "PutInlinePolicyToPermissionSet", in); e != nil {
			return e
		}
	} else if current["InlinePolicy"] != nil {
		if e := cfnComputeRun(ctx, h.commands, "ssoadmin", "DeleteInlinePolicyFromPermissionSet", base); e != nil {
			return e
		}
	}
	if raw := r.Properties["PermissionsBoundary"]; raw != nil {
		in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
		in["PermissionsBoundary"] = raw
		if e := cfnComputeRun(ctx, h.commands, "ssoadmin", "PutPermissionsBoundaryToPermissionSet", in); e != nil {
			return e
		}
	} else if current["PermissionsBoundary"] != nil {
		if e := cfnComputeRun(ctx, h.commands, "ssoadmin", "DeletePermissionsBoundaryFromPermissionSet", base); e != nil {
			return e
		}
	}
	in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
	in["TargetType"] = "ALL_PROVISIONED_ACCOUNTS"
	out, e := cfnOrgIdentityCall[api.ProvisionPermissionSetOutput](ctx, h.commands, "ssoadmin", "ProvisionPermissionSet", in)
	if e != nil {
		return e
	}
	if out.PermissionSetProvisioningStatus == nil || cfnComputeValue(out.PermissionSetProvisioningStatus.Status) != "SUCCEEDED" {
		return fmt.Errorf("permission set provisioning did not complete")
	}
	return nil
}
func (h cfnSSOPermissionSet) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	result := cfnOrgIdentityResult(r.PhysicalID, cloudformation.Properties{"PermissionSetArn": parts[0]})
	owned := cfnOrgIdentityContext(ctx, r)
	in := cfnComputeCopy(r.Properties, "Description", "SessionDuration")
	in["InstanceArn"] = parts[1]
	in["PermissionSetArn"] = parts[0]
	if r.Properties["RelayStateType"] != nil {
		in["RelayState"] = r.Properties["RelayStateType"]
	}
	if e = cfnComputeRun(owned, h.commands, "ssoadmin", "UpdatePermissionSet", in); e != nil {
		return result, e
	}
	if e = h.configure(owned, r); e != nil {
		return result, e
	}
	tags, e := cfnSSOTags(owned, h.commands, parts[1], parts[0])
	if e != nil {
		return result, e
	}
	return result, cfnSSOUpdateTags(owned, h.commands, r, parts[1], parts[0], tags)
}
func (h cfnSSOPermissionSet) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return e
	}
	return cfnComputeAbsent(cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "ssoadmin", "DeletePermissionSet", map[string]any{"InstanceArn": parts[1], "PermissionSetArn": parts[0]}))
}
func (h cfnSSOPermissionSet) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return nil, e
	}
	base := map[string]any{"InstanceArn": parts[1], "PermissionSetArn": parts[0]}
	out, e := cfnOrgIdentityCall[api.DescribePermissionSetOutput](ctx, h.commands, "ssoadmin", "DescribePermissionSet", base)
	if e != nil {
		return nil, e
	}
	v := out.PermissionSet
	tags, e := cfnSSOTags(ctx, h.commands, parts[1], parts[0])
	if e != nil {
		return nil, e
	}
	p := cloudformation.Properties{"InstanceArn": parts[1], "PermissionSetArn": parts[0], "Name": cfnComputeValue(v.Name), "Description": cfnComputeValue(v.Description), "SessionDuration": cfnComputeValue(v.SessionDuration), "RelayStateType": cfnComputeValue(v.RelayState), "Tags": cfnResourcePublicTags(tags)}
	var policies []any
	next := ""
	for {
		in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
		in["NextToken"] = next
		out, e := cfnOrgIdentityCall[api.ListManagedPoliciesInPermissionSetOutput](ctx, h.commands, "ssoadmin", "ListManagedPoliciesInPermissionSet", in)
		if e != nil {
			return nil, e
		}
		for _, v := range out.AttachedManagedPolicies {
			policies = append(policies, cfnComputeValue(v.Arn))
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			break
		}
	}
	p["ManagedPolicies"] = policies
	var refs []any
	next = ""
	for {
		in := cfnComputeCopy(base, "InstanceArn", "PermissionSetArn")
		in["NextToken"] = next
		out, e := cfnOrgIdentityCall[api.ListCustomerManagedPolicyReferencesInPermissionSetOutput](ctx, h.commands, "ssoadmin", "ListCustomerManagedPolicyReferencesInPermissionSet", in)
		if e != nil {
			return nil, e
		}
		for _, v := range out.CustomerManagedPolicyReferences {
			refs = append(refs, map[string]any{"Name": cfnComputeValue(v.Name), "Path": cfnComputeValue(v.Path)})
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			break
		}
	}
	p["CustomerManagedPolicyReferences"] = refs
	inline, e := cfnOrgIdentityCall[api.GetInlinePolicyForPermissionSetOutput](ctx, h.commands, "ssoadmin", "GetInlinePolicyForPermissionSet", base)
	if e != nil {
		return nil, e
	}
	if doc := cfnComputeValue(inline.InlinePolicy); doc != "" {
		var value any
		if e = json.Unmarshal([]byte(doc), &value); e != nil {
			return nil, e
		}
		p["InlinePolicy"] = value
	}
	boundary, e := cfnOrgIdentityCall[api.GetPermissionsBoundaryForPermissionSetOutput](ctx, h.commands, "ssoadmin", "GetPermissionsBoundaryForPermissionSet", base)
	if e != nil {
		return nil, e
	}
	if v := boundary.PermissionsBoundary; v != nil {
		b := map[string]any{}
		if v.ManagedPolicyArn != nil {
			b["ManagedPolicyArn"] = cfnComputeValue(v.ManagedPolicyArn)
		}
		if ref := v.CustomerManagedPolicyReference; ref != nil {
			b["CustomerManagedPolicyReference"] = map[string]any{"Name": cfnComputeValue(ref.Name), "Path": cfnComputeValue(ref.Path)}
		}
		p["PermissionsBoundary"] = b
	}
	return p, nil
}
func (h cfnSSOPermissionSet) arns(ctx context.Context, instance string) ([]string, error) {
	var arns []string
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListPermissionSetsOutput](ctx, h.commands, "ssoadmin", "ListPermissionSets", map[string]any{"InstanceArn": instance, "NextToken": next})
		if e != nil {
			return nil, e
		}
		for _, arn := range out.PermissionSets {
			arns = append(arns, string(arn))
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return arns, nil
		}
	}
}
func (h cfnSSOPermissionSet) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	instances := []string{cfnComputeString(r.Properties, "InstanceArn")}
	if instances[0] == "" {
		rows, e := (cfnSSOInstance(h)).List(ctx, r)
		if e != nil {
			return nil, e
		}
		instances = nil
		for _, v := range rows {
			instances = append(instances, v.Identifier)
		}
	}
	var rows []cloudformation.ResourceDescription
	for _, instance := range instances {
		arns, e := h.arns(ctx, instance)
		if e != nil {
			return nil, e
		}
		for _, arn := range arns {
			r.PhysicalID = cfnOrgIdentityID(arn, instance)
			p, e := h.Read(ctx, r)
			if e != nil {
				return nil, e
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
	}
	return rows, nil
}
