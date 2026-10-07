package integrations

import (
	"context"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/identitystore"
	"stackd/internal/services/ram"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ram-resourceshare.html
type cfnRAMResourceShare struct{ commands StepFunctionsCommands }

func (h cfnRAMResourceShare) Validate(p cloudformation.Properties) error {
	if e := cfnComputeProperties(p, "Name", "AllowExternalPrincipals", "ResourceShareConfiguration", "PermissionArns", "Principals", "ResourceArns", "Sources", "Tags"); e != nil {
		return e
	}
	if e := cfnComputeRequired(p, "Name"); e != nil {
		return e
	}
	if e := cfnComputeStrings(p, "Name"); e != nil {
		return e
	}
	if v, ok := p["AllowExternalPrincipals"]; ok {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("AllowExternalPrincipals must be boolean")
		}
	}
	for _, k := range []string{"PermissionArns", "Principals", "ResourceArns", "Sources"} {
		list, e := cfnComputeStringList(p, k)
		if e != nil {
			return e
		}
		if k == "Sources" && len(list) != 0 {
			return fmt.Errorf("configured RAM resource owners do not support source constraints")
		}
	}
	if raw := p["ResourceShareConfiguration"]; raw != nil {
		v, ok := cfnComputeObject(raw)
		if !ok {
			return fmt.Errorf("ResourceShareConfiguration must be an object")
		}
		if e := cfnComputeProperties(v, "RetainSharingOnAccountLeaveOrganization"); e != nil {
			return e
		}
		if raw, ok := v["RetainSharingOnAccountLeaveOrganization"]; ok {
			if _, ok := raw.(bool); !ok {
				return fmt.Errorf("RetainSharingOnAccountLeaveOrganization must be boolean")
			}
		}
	}
	_, e := cfnComputeTags(p)
	return e
}
func (h cfnRAMResourceShare) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ResourceShareConfiguration"), h.Validate(b)
}
func (h cfnRAMResourceShare) get(ctx context.Context, arn string) (*api.ResourceShare, error) {
	out, e := cfnOrgIdentityCall[api.GetResourceSharesResponse](ctx, h.commands, "ram", "GetResourceShares", map[string]any{"resourceOwner": "SELF", "resourceShareArns": []string{arn}})
	if e != nil {
		return nil, e
	}
	if len(out.ResourceShares) != 1 || cfnComputeValue(out.ResourceShares[0].Status) == "DELETED" {
		return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "Resource share not found", StatusCode: 400}
	}
	return &out.ResourceShares[0], nil
}

// Share ownership is the native owner's private record. Tags are public
// metadata only and never carry or prove ownership.
// cfnRAMShareView observes only edges recorded for the share's own owner, so
// separately owned associations are neither modeled nor reconciled as inline.
func cfnRAMShareView(ctx context.Context) context.Context {
	return ram.WithOwnedView(ram.WithShareAuthority(identitystore.WithCloudFormationOwner(ctx, "")))
}
func (h cfnRAMResourceShare) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	in := map[string]any{"name": r.Properties["Name"], "allowExternalPrincipals": cfnComputeDefault(r.Properties, "AllowExternalPrincipals", true), "clientToken": r.Token, "tags": cfnRAMWireTags(cfnOrgIdentityTags(r))}
	for _, k := range []string{"PermissionArns", "Principals", "ResourceArns"} {
		if r.Properties[k] != nil {
			in[string(k[0]+32)+k[1:]] = r.Properties[k]
		}
	}
	if v, ok := cfnComputeObject(r.Properties["ResourceShareConfiguration"]); ok {
		in["resourceShareConfiguration"] = map[string]any{"retainSharingOnAccountLeaveOrganization": cfnComputeDefault(v, "RetainSharingOnAccountLeaveOrganization", false)}
	}
	out, e := cfnOrgIdentityCall[api.CreateResourceShareResponse](cfnOrgIdentityClaim(ctx, r), h.commands, "ram", "CreateResourceShare", in)
	if e != nil {
		admitted, recovery := h.RecoverCreation(ctx, r)
		if recovery == nil {
			return admitted, e
		}
		return cloudformation.ResourceResult{}, e
	}
	if out.ResourceShare == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("RAM returned no resource share")
	}
	r.PhysicalID = cfnComputeValue(out.ResourceShare.ResourceShareArn)
	return cfnOrgIdentityRefreshResult(ctx, h, r)
}
func (h cfnRAMResourceShare) associations(ctx context.Context, arn, kind string) ([]api.ResourceShareAssociation, error) {
	var rows []api.ResourceShareAssociation
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.GetResourceShareAssociationsResponse](ctx, h.commands, "ram", "GetResourceShareAssociations", map[string]any{"resourceShareArns": []string{arn}, "associationType": kind, "nextToken": next})
		if e != nil {
			return nil, e
		}
		rows = append(rows, out.ResourceShareAssociations...)
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
	}
}
func (h cfnRAMResourceShare) permissions(ctx context.Context, arn string) ([]api.ResourceSharePermissionSummary, error) {
	var rows []api.ResourceSharePermissionSummary
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListResourceSharePermissionsResponse](ctx, h.commands, "ram", "ListResourceSharePermissions", map[string]any{"resourceShareArn": arn, "nextToken": next})
		if e != nil {
			return nil, e
		}
		rows = append(rows, out.Permissions...)
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
	}
}
func (h cfnRAMResourceShare) edges(ctx context.Context, arn, kind string) ([]string, error) {
	rows, e := h.associations(ctx, arn, kind)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, v := range rows {
		if cfnComputeValue(v.Status) != "DISASSOCIATED" {
			out = append(out, cfnComputeValue(v.AssociatedEntity))
		}
	}
	return out, nil
}
func (h cfnRAMResourceShare) defaultPermission(ctx context.Context, resourceType string) (string, error) {
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListPermissionsResponse](ctx, h.commands, "ram", "ListPermissions", map[string]any{"permissionType": "AWS_MANAGED", "resourceType": resourceType, "nextToken": next})
		if e != nil {
			return "", e
		}
		for _, p := range out.Permissions {
			if p.IsResourceTypeDefault != nil && bool(*p.IsResourceTypeDefault) {
				return cfnComputeValue(p.Arn), nil
			}
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return "", fmt.Errorf("no default RAM permission exists for %s", resourceType)
		}
	}
}

// resourceTypes returns the types of resources currently shared by any owner.
func (h cfnRAMResourceShare) resourceTypes(ctx context.Context, arn string) (map[string]bool, error) {
	types := map[string]bool{}
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.ListResourcesResponse](ctx, h.commands, "ram", "ListResources", map[string]any{"resourceOwner": "SELF", "resourceShareArns": []string{arn}, "nextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.Resources {
			types[cfnComputeValue(v.Type)] = true
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return types, nil
		}
	}
}
func cfnRAMHasPermission(rows []api.ResourceSharePermissionSummary, arn string) bool {
	return slices.ContainsFunc(rows, func(v api.ResourceSharePermissionSummary) bool { return cfnComputeValue(v.Arn) == arn })
}

// cfnRAMSharePlan changes only edges recorded for the share's owner. Separately
// owned edges are preserved; a desired inline edge another owner holds is
// rejected before any effect instead of being adopted or removed.
type cfnRAMSharePlan struct {
	add, remove map[string][]string
	permissions []string
}

func (h cfnRAMResourceShare) plan(ctx context.Context, r cloudformation.ResourceRequest) (cfnRAMSharePlan, error) {
	owned := ram.WithOwnedView(ctx)
	plan := cfnRAMSharePlan{add: map[string][]string{}, remove: map[string][]string{}}
	for _, k := range []string{"ResourceArns", "Principals"} {
		kind := "RESOURCE"
		if k == "Principals" {
			kind = "PRINCIPAL"
		}
		desired, e := cfnComputeStringList(r.Properties, k)
		if e != nil {
			return plan, e
		}
		live, e := h.edges(ctx, r.PhysicalID, kind)
		if e != nil {
			return plan, e
		}
		mine, e := h.edges(owned, r.PhysicalID, kind)
		if e != nil {
			return plan, e
		}
		key := string(k[0]+32) + k[1:]
		for _, id := range live {
			if slices.Contains(mine, id) {
				if !slices.Contains(desired, id) {
					plan.remove[key] = append(plan.remove[key], id)
				}
			} else if slices.Contains(desired, id) {
				return plan, fmt.Errorf("%s %s is owned by a separate association", k, id)
			}
		}
		for _, id := range desired {
			if !slices.Contains(live, id) && !slices.Contains(plan.add[key], id) {
				plan.add[key] = append(plan.add[key], id)
			}
		}
	}
	live, e := h.permissions(ctx, r.PhysicalID)
	if e != nil {
		return plan, e
	}
	mine, e := h.permissions(owned, r.PhysicalID)
	if e != nil {
		return plan, e
	}
	desired, e := cfnComputeStringList(r.Properties, "PermissionArns")
	if e != nil {
		return plan, e
	}
	if len(desired) == 0 {
		// No explicit permissions selects the managed default for each type the share owns.
		for _, v := range mine {
			arn, e := h.defaultPermission(ctx, cfnComputeValue(v.ResourceType))
			if e != nil {
				return plan, e
			}
			if !slices.Contains(desired, arn) {
				desired = append(desired, arn)
			}
		}
	}
	for _, arn := range desired {
		if cfnRAMHasPermission(live, arn) {
			if !cfnRAMHasPermission(mine, arn) {
				return plan, fmt.Errorf("PermissionArns %s is owned by a separate permission association", arn)
			}
			continue
		}
		p, e := cfnRAMPermission(h).get(identitystore.WithCloudFormationOwner(ctx, ""), arn)
		if e != nil {
			return plan, e
		}
		for _, v := range live {
			if cfnComputeValue(v.ResourceType) == cfnComputeValue(p.ResourceType) && !cfnRAMHasPermission(mine, cfnComputeValue(v.Arn)) {
				return plan, fmt.Errorf("PermissionArns %s would replace separately owned permission %s", arn, cfnComputeValue(v.Arn))
			}
		}
	}
	plan.permissions = desired
	return plan, nil
}
func (h cfnRAMResourceShare) apply(ctx context.Context, arn string, plan cfnRAMSharePlan) error {
	keys := []string{"resourceArns", "principals"}
	for _, key := range keys {
		if len(plan.remove[key]) > 0 {
			if e := cfnComputeRun(ctx, h.commands, "ram", "DisassociateResourceShare", map[string]any{"resourceShareArn": arn, key: plan.remove[key]}); e != nil {
				return e
			}
		}
	}
	for _, key := range keys {
		if len(plan.add[key]) > 0 {
			if e := cfnComputeRun(ctx, h.commands, "ram", "AssociateResourceShare", map[string]any{"resourceShareArn": arn, key: plan.add[key]}); e != nil {
				return e
			}
		}
	}
	live, e := h.permissions(ctx, arn)
	if e != nil {
		return e
	}
	for _, p := range plan.permissions {
		if cfnRAMHasPermission(live, p) {
			continue
		}
		if e := cfnComputeRun(ctx, h.commands, "ram", "AssociateResourceSharePermission", map[string]any{"resourceShareArn": arn, "permissionArn": p, "replace": true}); e != nil {
			return e
		}
	}
	// A type with live resources keeps its permission, as RAM requires; desired
	// replacements for such types were applied above.
	required, e := h.resourceTypes(ctx, arn)
	if e != nil {
		return e
	}
	mine, e := h.permissions(ram.WithOwnedView(ctx), arn)
	if e != nil {
		return e
	}
	for _, v := range mine {
		p := cfnComputeValue(v.Arn)
		if slices.Contains(plan.permissions, p) || required[cfnComputeValue(v.ResourceType)] {
			continue
		}
		if e := cfnComputeRun(ctx, h.commands, "ram", "DisassociateResourceSharePermission", map[string]any{"resourceShareArn": arn, "permissionArn": p}); e != nil {
			return e
		}
	}
	return nil
}
func (h cfnRAMResourceShare) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if e := h.Validate(r.Properties); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	// CloudFormation acts for its exact incarnation; Cloud Control acts for the
	// share's recorded owner under current IAM. Neither bypasses edge ownership.
	authority := ram.WithShareAuthority(cfnOrgIdentityContext(ctx, r))
	if _, e := h.get(authority, r.PhysicalID); e != nil {
		return cloudformation.ResourceResult{}, e
	}
	result := cfnOrgIdentityResult(r.PhysicalID, cloudformation.Properties{"Arn": r.PhysicalID})
	plan, e := h.plan(authority, r)
	if e != nil {
		return result, e
	}
	allow, _ := cfnComputeDefault(r.Properties, "AllowExternalPrincipals", true).(bool)
	settings := func() error {
		return cfnComputeRun(authority, h.commands, "ram", "UpdateResourceShare", map[string]any{"resourceShareArn": r.PhysicalID, "name": r.Properties["Name"], "allowExternalPrincipals": allow})
	}
	// External principals must be allowed before they are added and removed before they are disallowed.
	if allow {
		if e = settings(); e != nil {
			return result, e
		}
	}
	if e = h.apply(authority, r.PhysicalID, plan); e != nil {
		return result, e
	}
	if !allow {
		if e = settings(); e != nil {
			return result, e
		}
	}
	v, e := h.get(authority, r.PhysicalID)
	if e != nil {
		return result, e
	}
	return result, cfnRAMUpdateTags(authority, h.commands, r.PhysicalID, cfnRAMTags(v.Tags), cfnOrgIdentityTags(r))
}
func (h cfnRAMResourceShare) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return nil
	}
	ownerCtx := cfnOrgIdentityContext(ctx, r)
	if _, e := h.get(ownerCtx, r.PhysicalID); cfnRAMMissing(e) {
		return nil
	} else if e != nil {
		return e
	}
	e := cfnComputeRun(ownerCtx, h.commands, "ram", "DeleteResourceShare", map[string]any{"resourceShareArn": r.PhysicalID})
	if cfnRAMMissing(e) {
		return nil
	}
	return e
}
func (h cfnRAMResourceShare) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, e := h.get(ctx, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	view := cfnRAMShareView(ctx)
	p := cloudformation.Properties{"Arn": r.PhysicalID, "Name": cfnComputeValue(v.Name), "AllowExternalPrincipals": v.AllowExternalPrincipals, "Status": cfnComputeValue(v.Status), "OwningAccountId": cfnComputeValue(v.OwningAccountId), "FeatureSet": cfnComputeValue(v.FeatureSet), "CreationTime": v.CreationTime, "LastUpdatedTime": v.LastUpdatedTime, "Tags": cfnOrgIdentityPublicTags(cfnRAMTags(v.Tags))}
	if v.ResourceShareConfiguration != nil {
		p["ResourceShareConfiguration"] = map[string]any{"RetainSharingOnAccountLeaveOrganization": v.ResourceShareConfiguration.RetainSharingOnAccountLeaveOrganization}
	}
	for _, k := range []string{"ResourceArns", "Principals"} {
		kind := "RESOURCE"
		if k == "Principals" {
			kind = "PRINCIPAL"
		}
		associations, e := h.associations(view, r.PhysicalID, kind)
		if e != nil {
			return nil, e
		}
		list := []any{}
		for _, a := range associations {
			status := cfnComputeValue(a.Status)
			if status != "DISASSOCIATED" {
				list = append(list, cfnComputeValue(a.AssociatedEntity))
			}
		}
		p[k] = list
	}
	permissions, e := h.permissions(view, r.PhysicalID)
	if e != nil {
		return nil, e
	}
	list := []any{}
	for _, v := range permissions {
		list = append(list, cfnComputeValue(v.Arn))
	}
	p["PermissionArns"] = list
	return p, nil
}
func (h cfnRAMResourceShare) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, e := h.Read(ctx, r)
	if e != nil {
		return cloudformation.ResourceResult{}, e
	}
	return cfnOrgIdentityResult(r.PhysicalID, p), nil
}
func (h cfnRAMResourceShare) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.GetResourceSharesResponse](ctx, h.commands, "ram", "GetResourceShares", map[string]any{"resourceOwner": "SELF", "resourceShareStatus": "ACTIVE", "nextToken": next})
		if e != nil {
			return nil, e
		}
		for _, v := range out.ResourceShares {
			if cfnComputeValue(v.FeatureSet) != "STANDARD" {
				continue
			}
			r.PhysicalID = cfnComputeValue(v.ResourceShareArn)
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

func (h cfnRAMResourceShare) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = ram.WithShareOwnerView(cfnOrgIdentityClaim(ctx, r))
	next := ""
	for {
		out, e := cfnOrgIdentityCall[api.GetResourceSharesResponse](ctx, h.commands, "ram", "GetResourceShares", map[string]any{"resourceOwner": "SELF", "resourceShareStatus": "ACTIVE", "nextToken": next})
		if e != nil {
			return cloudformation.ResourceResult{}, cfnOrgIdentityUnobserved(e)
		}
		if len(out.ResourceShares) > 0 {
			r.PhysicalID = cfnComputeValue(out.ResourceShares[0].ResourceShareArn)
			return cfnOrgIdentityRefreshResult(ctx, h, r)
		}
		next = cfnComputeValue(out.NextToken)
		if next == "" {
			return cloudformation.ResourceResult{}, cfnOrgIdentityNotFound("share was not created by this incarnation")
		}
	}
}

func (h cfnRAMResourceShare) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = ram.WithShareOwnerView(cfnOrgIdentityContext(ctx, r))
	v, e := h.get(ctx, r.PhysicalID)
	if e != nil {
		return false, e
	}
	if status := cfnComputeValue(v.Status); status == "FAILED" {
		return false, fmt.Errorf("resource share creation failed")
	} else if status != "ACTIVE" {
		return false, nil
	}
	view := cfnRAMShareView(ctx)
	for _, kind := range []string{"RESOURCE", "PRINCIPAL"} {
		rows, e := h.associations(view, r.PhysicalID, kind)
		if e != nil {
			return false, e
		}
		for _, v := range rows {
			switch cfnComputeValue(v.Status) {
			case "FAILED", "SUSPENDED":
				return false, fmt.Errorf("RAM %s association %s failed: %s", kind, cfnComputeValue(v.AssociatedEntity), cfnComputeValue(v.StatusMessage))
			case "ASSOCIATING":
				if kind == "RESOURCE" {
					return false, nil
				}
			}
		}
	}
	return true, nil
}
