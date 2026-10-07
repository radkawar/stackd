package integrations

import (
	"context"
	"fmt"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ram"
)

func cfnRAMAssociationValidate(p cloudformation.Properties, entity string) error {
	if e := cfnComputeProperties(p, "ResourceShareArn", entity); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "ResourceShareArn", entity); e != nil {
		return e
	}
	return cfnComputeStrings(p, "ResourceShareArn", entity)
}

// cfnRAMAssociationClaim proves through the owner's private edge record, never
// public tags, that this exact incarnation admitted the live edge.
func cfnRAMAssociationClaim(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, kind, entity string) error {
	if r.CloudControl {
		return nil
	}
	owned := ram.WithOwnedView(cfnOrgIdentityContext(ctx, r))
	var e error
	if kind == "PERMISSION" {
		_, e = (cfnRAMPermissionAssociation{c}).Read(owned, r)
	} else {
		_, e = cfnRAMAssociationRead(owned, c, r, kind, entity)
	}
	if cfnRAMMissing(e) {
		return fmt.Errorf("%s association is not owned by this CloudFormation incarnation", entity)
	}
	return e
}
func cfnRAMAssociationRead(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, kind, entity string) (cloudformation.Properties, error) {
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return nil, e
	}
	if _, e := (cfnRAMResourceShare{c}).get(ctx, parts[0]); e != nil {
		return nil, e
	}
	rows, e := (cfnRAMResourceShare{c}).associations(ctx, parts[0], kind)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if cfnComputeValue(v.AssociatedEntity) == parts[1] && cfnComputeValue(v.Status) != "DISASSOCIATED" {
			return cloudformation.Properties{"ResourceShareArn": parts[0], entity: parts[1], "AssociationType": cfnComputeValue(v.AssociationType), "Status": cfnComputeValue(v.Status), "CreationTime": v.CreationTime, "LastUpdatedTime": v.LastUpdatedTime, "External": v.External}, nil
		}
	}
	return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Resource share association was not found", StatusCode: 400}
}
func cfnRAMAssociationList(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, kind, entity string) ([]cloudformation.ResourceDescription, error) {
	share := cfnComputeString(r.Properties, "ResourceShareArn")
	var shares []string
	if share != "" {
		shares = []string{share}
	} else {
		rows, e := (cfnRAMResourceShare{c}).List(ctx, r)
		if e != nil {
			return nil, e
		}
		for _, v := range rows {
			shares = append(shares, v.Identifier)
		}
	}
	var rows []cloudformation.ResourceDescription
	for _, share := range shares {
		associations, e := (cfnRAMResourceShare{c}).associations(ctx, share, kind)
		if e != nil {
			return nil, e
		}
		for _, a := range associations {
			if cfnComputeValue(a.Status) == "DISASSOCIATED" {
				continue
			}
			r.PhysicalID = cfnOrgIdentityID(share, cfnComputeValue(a.AssociatedEntity))
			p, e := cfnRAMAssociationRead(ctx, c, r, kind, entity)
			if e != nil {
				return nil, e
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
		}
	}
	return rows, nil
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ram-resourceassociation.html
type cfnRAMResourceAssociation struct{ commands StepFunctionsCommands }

func (h cfnRAMResourceAssociation) Validate(p cloudformation.Properties) error {
	return cfnRAMAssociationValidate(p, "ResourceArn")
}
func (h cfnRAMResourceAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ResourceShareArn", "ResourceArn"), h.Validate(b)
}
func (h cfnRAMResourceAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	ownerCtx := cfnOrgIdentityClaim(ctx, r)
	id := cfnOrgIdentityID(cfnComputeString(r.Properties, "ResourceShareArn"), cfnComputeString(r.Properties, "ResourceArn"))
	r.PhysicalID = id
	result := cfnOrgIdentityResult(id, cloudformation.Properties{})
	e := cfnComputeRun(ownerCtx, h.commands, "ram", "AssociateResourceShare", map[string]any{"resourceShareArn": r.Properties["ResourceShareArn"], "resourceArns": []any{r.Properties["ResourceArn"]}})
	if e != nil {
		admitted, recovery := h.RecoverCreation(ctx, r)
		if recovery == nil {
			return admitted, e
		}
		return cloudformation.ResourceResult{}, e
	}
	p, e := h.Read(ctx, r)
	if e != nil {
		return result, e
	}
	return cfnOrgIdentityResult(id, p), nil
}
func (h cfnRAMResourceAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := cfnRAMAssociationClaim(ctx, h.commands, r, "RESOURCE", "ResourceArn"); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p, e := h.Read(ctx, r)
	return cfnOrgIdentityResult(r.PhysicalID, p), e
}
func (h cfnRAMResourceAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	if _, e := h.Read(ctx, r); cfnRAMMissing(e) {
		return nil
	} else if e != nil {
		return e
	}
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return e
	}
	if e = cfnRAMAssociationClaim(ctx, h.commands, r, "RESOURCE", "ResourceArn"); e != nil {
		return e
	}
	return cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "ram", "DisassociateResourceShare", map[string]any{"resourceShareArn": parts[0], "resourceArns": []string{parts[1]}})
}
func (h cfnRAMResourceAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return cfnRAMAssociationRead(ctx, h.commands, r, "RESOURCE", "ResourceArn")
}
func (h cfnRAMResourceAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnRAMAssociationList(ctx, h.commands, r, "RESOURCE", "ResourceArn")
}
func (h cfnRAMResourceAssociation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.PhysicalID = cfnOrgIdentityID(cfnComputeString(r.Properties, "ResourceShareArn"), cfnComputeString(r.Properties, "ResourceArn"))
	p, e := h.Read(ram.WithOwnedView(cfnOrgIdentityClaim(ctx, r)), r)
	if cfnRAMMissing(e) {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("resource association was not created by this incarnation")
	}
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ram-principalassociation.html
type cfnRAMPrincipalAssociation struct{ commands StepFunctionsCommands }

func (h cfnRAMPrincipalAssociation) Validate(p cloudformation.Properties) error {
	return cfnRAMAssociationValidate(p, "Principal")
}
func (h cfnRAMPrincipalAssociation) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ResourceShareArn", "Principal"), h.Validate(b)
}
func (h cfnRAMPrincipalAssociation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	ownerCtx := cfnOrgIdentityClaim(ctx, r)
	id := cfnOrgIdentityID(cfnComputeString(r.Properties, "ResourceShareArn"), cfnComputeString(r.Properties, "Principal"))
	r.PhysicalID = id
	result := cfnOrgIdentityResult(id, cloudformation.Properties{})
	e := cfnComputeRun(ownerCtx, h.commands, "ram", "AssociateResourceShare", map[string]any{"resourceShareArn": r.Properties["ResourceShareArn"], "principals": []any{r.Properties["Principal"]}})
	if e != nil {
		admitted, recovery := h.RecoverCreation(ctx, r)
		if recovery == nil {
			return admitted, e
		}
		return cloudformation.ResourceResult{}, e
	}
	p, e := h.Read(ctx, r)
	if e != nil {
		return result, e
	}
	return cfnOrgIdentityResult(id, p), nil
}
func (h cfnRAMPrincipalAssociation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := cfnRAMAssociationClaim(ctx, h.commands, r, "PRINCIPAL", "Principal"); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	p, e := h.Read(ctx, r)
	return cfnOrgIdentityResult(r.PhysicalID, p), e
}
func (h cfnRAMPrincipalAssociation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	if _, e := h.Read(ctx, r); cfnRAMMissing(e) {
		return nil
	} else if e != nil {
		return e
	}
	parts, e := cfnOrgIdentityParts(r.PhysicalID, 2)
	if e != nil {
		return e
	}
	if e = cfnRAMAssociationClaim(ctx, h.commands, r, "PRINCIPAL", "Principal"); e != nil {
		return e
	}
	return cfnComputeRun(cfnOrgIdentityContext(ctx, r), h.commands, "ram", "DisassociateResourceShare", map[string]any{"resourceShareArn": parts[0], "principals": []string{parts[1]}})
}
func (h cfnRAMPrincipalAssociation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return cfnRAMAssociationRead(ctx, h.commands, r, "PRINCIPAL", "Principal")
}
func (h cfnRAMPrincipalAssociation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	return cfnRAMAssociationList(ctx, h.commands, r, "PRINCIPAL", "Principal")
}
func (h cfnRAMPrincipalAssociation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.PhysicalID = cfnOrgIdentityID(cfnComputeString(r.Properties, "ResourceShareArn"), cfnComputeString(r.Properties, "Principal"))
	p, e := h.Read(ram.WithOwnedView(cfnOrgIdentityClaim(ctx, r)), r)
	if cfnRAMMissing(e) {
		return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("principal association was not created by this incarnation")
	}
	if e != nil {
		return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}

func (h cfnRAMResourceAssociation) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	if e := cfnRAMAssociationClaim(ctx, h.commands, r, "RESOURCE", "ResourceArn"); e != nil {
		return false, e
	}
	p, e := h.Read(ctx, r)
	if e != nil {
		return false, e
	}
	switch cfnComputeString(p, "Status") {
	case "ASSOCIATED":
		return true, nil
	case "FAILED", "SUSPENDED":
		return false, fmt.Errorf("RAM resource association failed")
	}
	return false, nil
}
func (h cfnRAMPrincipalAssociation) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	if e := cfnRAMAssociationClaim(ctx, h.commands, r, "PRINCIPAL", "Principal"); e != nil {
		return false, e
	}
	p, e := h.Read(ctx, r)
	if e != nil {
		return false, e
	}
	switch cfnComputeString(p, "Status") {
	case "ASSOCIATED", "ASSOCIATING":
		return true, nil
	case "FAILED", "SUSPENDED":
		return false, fmt.Errorf("RAM principal association failed")
	}
	return false, nil
}
