package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ram"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ram-permissionassociation.html
type cfnRAMPermissionAssociation struct{ commands StepFunctionsCommands }

func (h cfnRAMPermissionAssociation) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "ResourceShareArn", "PermissionArn", "Replace"); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "ResourceShareArn", "PermissionArn"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "ResourceShareArn", "PermissionArn"); e != nil {
		return e
	}
	if v, ok := p["Replace"]; ok {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("replace must be boolean")
		}
	}
	return nil
}
func (h cfnRAMPermissionAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ResourceShareArn", "PermissionArn"), h.Validate(b)
}
func (h cfnRAMPermissionAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	ownerCtx := cfnOrgIdentityClaim(ctx, r)
	r.PhysicalID = cfnOrgIdentityID(cfnComputeString(r.Properties, "ResourceShareArn"), cfnComputeString(r.Properties, "PermissionArn"))
	if _, e := h.Read(ctx, r); e == nil {
		claim := r
		claim.CloudControl = false
		if e := cfnRAMAssociationClaim(ownerCtx, h.commands, claim, "PERMISSION", "PermissionArn"); e != nil {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, e)
		}
		return cfnOrgIdentityRefreshResult(ctx, h, r)
	} else if !cfnRAMMissing(e) {
		return cloudformation.ResourceResult{}, e
	}
	e := cfnComputeRun(ownerCtx, h.commands, "ram", "AssociateResourceSharePermission", map[string]any{"resourceShareArn": r.Properties["ResourceShareArn"], "permissionArn": r.Properties["PermissionArn"], "replace": cfnComputeDefault(r.Properties, "Replace", false)})
	if e != nil {
		admitted, recovery := h.RecoverCreation(ctx, r)
		if recovery == nil {
			return admitted, e
		}
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnRAMPermissionAssociation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.PhysicalID = cfnOrgIdentityID(cfnComputeString(r.Properties, "ResourceShareArn"), cfnComputeString(r.Properties, "PermissionArn"))
	p, e := h.Read(ram.WithOwnedView(cfnOrgIdentityClaim(ctx, r)), r)
	if cfnRAMMissing(e) {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("permission association was not created by this incarnation")
	}
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnRAMPermissionAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	if e := cfnRAMAssociationClaim(ctx, h.commands, r, "PERMISSION", "PermissionArn"); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnRAMPermissionAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	if _, e := h.Read(ctx, r); cfnRAMMissing(e) {
		return nil
	} else if e != nil {
		return e
	}
	if e := cfnRAMAssociationClaim(ctx, h.commands, r, "PERMISSION", "PermissionArn"); e != nil {
		return e
	}
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return e
	}
	return cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "ram", "DisassociateResourceSharePermission", map[string]any{"resourceShareArn": parts[0], "permissionArn": parts[1]})
}
func (h cfnRAMPermissionAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return nil, e
	}
	if _, e := cfnRAMResourceShare(h).get(ctx, parts[0]); e != nil {
		return nil, e
	}
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListPermissionAssociationsResponse](ctx, h.commands, "ram", "ListPermissionAssociations", map[string]any{"permissionArn": parts[1], "nextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.Permissions {
			if cfnComputeValue(v.ResourceShareArn) == parts[0] && cfnComputeValue(v.Arn) == parts[1] {
				return cloudformation.Properties{"ResourceShareArn": parts[0], "PermissionArn": parts[1], "IsDefault": v.DefaultVersion, "AssociationStatus": cfnComputeValue(v.Status), "LastUpdatedTime": v.LastUpdatedTime, "FeatureSet": cfnComputeValue(v.FeatureSet), "ResourceType": cfnComputeValue(v.ResourceType), "PermissionVersion": cfnComputeValue(v.PermissionVersion)}, nil
			}
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Permission association not found", StatusCode: 400}
		}
	}
}
func (h cfnRAMPermissionAssociation) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnRAMPermissionAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListPermissionAssociationsResponse](ctx, h.commands, "ram", "ListPermissionAssociations", map[string]any{"nextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.Permissions {
			r.PhysicalID = cfnOrgIdentityID(cfnComputeValue(v.ResourceShareArn), cfnComputeValue(v.Arn))
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
