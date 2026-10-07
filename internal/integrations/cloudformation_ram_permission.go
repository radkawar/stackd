package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/services/cloudformation"
)

func cfnRAMTags(tags api.TagList) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		out[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
	}
	return out
}
func cfnRAMWireTags(tags map[string]string) []map[string]string {
	out := cfnComputeTagList(tags)
	for _, t := range out {
		t["key"], t["value"] = t["Key"], t["Value"]
		delete(t, "Key")
		delete(t, "Value")
	}
	return out
}
func cfnRAMUpdateTags(ctx context.Context, c StepFunctionsCommands, arn string, current, desired map[string]string) error {
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if e := cfnComputeRun(ctx, c, "ram", "UntagResource", map[string]any{"resourceArn": arn, "tagKeys": removed}); e != nil {
			return e
		}
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, "ram", "TagResource", map[string]any{"resourceArn": arn, "tags": cfnRAMWireTags(desired)})
}
func cfnRAMMissing(e error) bool {
	return cfnMessagingMissing(e, "UnknownResourceException", "ResourceNotFoundException")
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ram-permission.html
type cfnRAMPermission struct{ commands StepFunctionsCommands }

func (h cfnRAMPermission) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "Name", "ResourceType", "PolicyTemplate", "Tags"); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "Name", "ResourceType", "PolicyTemplate"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "Name", "ResourceType"); e != nil {
		return e
	}
	if _, e := cfnComputeDocument(p["PolicyTemplate"]); e != nil {
		return e
	}
	_, e := cfnComputeTags(p)
	return e
}
func (h cfnRAMPermission) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "ResourceType", "PolicyTemplate"), h.Validate(b)
}
func (h cfnRAMPermission) get(ctx context.Context, id string) (*api.ResourceSharePermissionDetail, error) {
	out, e := cfnOrgIdentityCall[api.GetPermissionResponse](ctx, h.commands, "ram", "GetPermission", map[string]any{"permissionArn": id})
	if e != nil {
		return nil, e
	}
	if out.Permission == nil {
		return nil, fmt.Errorf("RAM returned no permission")
	}
	if cfnComputeValue(out.Permission.Status) == "DELETED" {
		return nil, cfnOrgIdentityNotFound("RAM permission was deleted")
	}
	return out.Permission, nil
}
func (h cfnRAMPermission) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	doc, e := cfnComputeDocument(r.Properties["PolicyTemplate"])
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	ctx = cfnOrgIdentityClaim(ctx, r)
	out, e := cfnOrgIdentityCall[api.CreatePermissionResponse](ctx, h.commands, "ram", "CreatePermission", map[string]any{"name": r.Properties["Name"], "resourceType": r.Properties["ResourceType"], "policyTemplate": doc, "clientToken": r.Token, "tags": cfnRAMWireTags(cfnOrgIdentityTags(r))})
	if e != nil {
		admitted, recovery := h.RecoverCreation(ctx, r)
		if recovery == nil {
			return admitted, e
		}
		return cloudformation.ResourceResult{}, e
	}
	if out.Permission == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("RAM returned no permission")
	}
	r.PhysicalID = cfnComputeValue(out.Permission.Arn)
	if _, e = h.get(ctx, r.PhysicalID); e != nil {
		return cfnOrgIdentityResult(r.PhysicalID, cloudformation.Properties{"Arn": r.PhysicalID}), e
	}
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnRAMPermission) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnOrgIdentityClaim(ctx, r)
	rows, e := h.List(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	if len(rows) == 0 {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("permission was not created by this incarnation")
	}
	r.PhysicalID = rows[0].Identifier
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnRAMPermission) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	ctx = cfnOrgIdentityContext(ctx, r)
	v, e := h.get(ctx, r.PhysicalID)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	tags := cfnRAMTags(v.Tags)
	if cfnComputeChanged(r.Previous, r.Properties, "Name", "ResourceType", "PolicyTemplate") {
		return cloudformation.ResourceResult{}, fmt.Errorf("RAM permission identity changes require replacement")
	}
	e = cfnRAMUpdateTags(ctx, h.commands, r.PhysicalID, tags, cfnOrgIdentityTags(r))
	result, re := cfnOrgIdentityRefreshResult(ctx, h, r)
	if e != nil {
		return result, e
	}
	return result, re
}
func (h cfnRAMPermission) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	ctx = cfnOrgIdentityContext(ctx, r)
	if _, e := h.get(ctx, r.PhysicalID); cfnRAMMissing(e) {
		return nil
	} else if e != nil {
		return e
	}
	e := cfnComputeRun(ctx, h.commands, "ram", "DeletePermission", map[string]any{"permissionArn": r.PhysicalID})
	if cfnRAMMissing(e) {
		return nil
	}
	return e
}
func (h cfnRAMPermission) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.get(ctx, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	var doc any
	if e = json.Unmarshal([]byte(cfnComputeValue(v.Permission)), &doc); e != nil {
		return nil, e
	}
	return cloudformation.Properties{"Arn": r.PhysicalID, "Name": cfnComputeValue(v.Name), "ResourceType": cfnComputeValue(v.ResourceType), "PolicyTemplate": doc, "PermissionType": cfnComputeValue(v.PermissionType), "Version": cfnComputeValue(v.Version), "IsResourceTypeDefault": v.IsResourceTypeDefault, "Tags": cfnOrgIdentityPublicTags(cfnRAMTags(v.Tags))}, nil
}
func (h cfnRAMPermission) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnRAMPermission) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListPermissionsResponse](ctx, h.commands, "ram", "ListPermissions", map[string]any{"permissionType": "CUSTOMER_MANAGED", "nextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.Permissions {
			r.PhysicalID = cfnComputeValue(v.Arn)
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
