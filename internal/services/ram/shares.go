package ram

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/services/identitystore"
	"strings"
	"time"
)

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

func (s *Service) ownedShare(r Reader, arn, op string, mutable bool) (Share, error) {
	v, e := r.Share(arn)
	if e != nil {
		return v, e
	}
	if v.Scope != scopeFor(r.Context()) {
		return Share{}, ErrNotFound
	}
	if e = s.authorize(r, op, v.ARN, v.Tags); e != nil {
		return Share{}, e
	}
	if mutable && (v.Status != "ACTIVE" || v.FeatureSet != "STANDARD") {
		return Share{}, failure("InvalidStateTransitionException", "The resource share cannot be modified in its current state.")
	}
	return v, nil
}
func apiShare(v Share) *api.ResourceShare {
	return &api.ResourceShare{ResourceShareArn: new(api.String(v.ARN)), Name: new(api.String(v.Name)), OwningAccountId: new(api.String(v.AccountID)), AllowExternalPrincipals: new(api.Boolean(v.AllowExternal)), Status: new(api.ResourceShareStatus(v.Status)), FeatureSet: new(api.ResourceShareFeatureSet(v.FeatureSet)), CreationTime: &v.Created, LastUpdatedTime: &v.Updated, Tags: apiTags(v.Tags), ResourceShareConfiguration: &api.ResourceShareConfiguration{RetainSharingOnAccountLeaveOrganization: new(api.Boolean(v.RetainOnLeave))}}
}
func apiAssociation(v Share, entity, kind, status string, external bool, created, updated time.Time) api.ResourceShareAssociation {
	return api.ResourceShareAssociation{ResourceShareArn: new(api.String(v.ARN)), ResourceShareName: new(api.String(v.Name)), AssociatedEntity: new(api.String(entity)), AssociationType: new(api.ResourceShareAssociationType(kind)), Status: new(api.ResourceShareAssociationStatus(status)), External: new(api.Boolean(external)), CreationTime: &created, LastUpdatedTime: &updated}
}
func (s *Service) createResourceShare(tx Transaction, in *api.CreateResourceShareRequest) (*api.CreateResourceShareResponse, error) {
	if e := s.authorize(tx, "CreateResourceShare", "", nil); e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "CreateResourceShare", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if replay {
		v, e := tx.Share(rec.ARN)
		if e != nil {
			return nil, e
		}
		if e = checkShareOwner(tx.Context(), v); e != nil {
			return nil, e
		}
		if v.Scope != scopeFor(tx.Context()) || identitystore.CloudFormationOwner(tx.Context()) != "" && v.Status != "ACTIVE" {
			return nil, ErrNotFound
		}
		if e = s.authorize(tx, "CreateResourceShare", v.ARN, v.Tags); e != nil {
			return nil, e
		}
		return &api.CreateResourceShareResponse{ClientToken: in.ClientToken, ResourceShare: apiShare(v)}, nil
	}
	name := value(in.Name)
	if strings.TrimSpace(name) == "" || len(name) > 255 {
		return nil, failure("InvalidParameterException", "A resource share name must contain 1 to 255 characters.")
	}
	if len(in.Sources) > 0 {
		return nil, failure("InvalidParameterException", "Configured resource owners do not support service principal source constraints.")
	}
	tags, e := readTags(in.Tags)
	if e != nil {
		return nil, e
	}
	now := s.clock.Now()
	v := Share{Scope: scopeFor(tx.Context()), Name: name, Status: "ACTIVE", FeatureSet: "STANDARD", AllowExternal: true, Created: now, Updated: now, Tags: tags, CloudFormationOwner: identitystore.CloudFormationOwner(tx.Context())}
	v.ARN = arnFor(v.Scope, "resource-share", identifier())
	if in.AllowExternalPrincipals != nil {
		v.AllowExternal = bool(*in.AllowExternalPrincipals)
	}
	if in.ResourceShareConfiguration != nil && in.ResourceShareConfiguration.RetainSharingOnAccountLeaveOrganization != nil {
		v.RetainOnLeave = bool(*in.ResourceShareConfiguration.RetainSharingOnAccountLeaveOrganization)
	}
	if v.RetainOnLeave && !v.AllowExternal {
		return nil, failure("InvalidParameterException", "Retaining sharing when an account leaves requires external principals.")
	}
	for _, arn := range in.PermissionArns {
		p, e := s.permission(tx, string(arn))
		if e != nil {
			return nil, e
		}
		if p.Status == "DELETED" || p.FeatureSet != "STANDARD" {
			return nil, failure("InvalidParameterException", "Permission is not attachable.")
		}
		for _, a := range v.Permissions {
			if a.ResourceType == p.ResourceType {
				return nil, failure("InvalidParameterException", "Only one permission per resource type is allowed.")
			}
		}
		v.Permissions = append(v.Permissions, PermissionAssociation{ARN: p.ARN, ResourceType: p.ResourceType, Version: p.DefaultVersion, CloudFormationOwner: v.CloudFormationOwner})
	}
	if _, e = s.addAssociations(tx, &v, in.ResourceArns, in.Principals, v.CloudFormationOwner); e != nil {
		return nil, e
	}
	if e = tx.PutShare(v); e != nil {
		return nil, e
	}
	rec.ARN = v.ARN
	if e = saveReceipt(tx, rec); e != nil {
		return nil, e
	}
	return &api.CreateResourceShareResponse{ClientToken: in.ClientToken, ResourceShare: apiShare(v)}, nil
}
func (s *Service) updateResourceShare(tx Transaction, in *api.UpdateResourceShareRequest) (*api.UpdateResourceShareResponse, error) {
	v, e := s.ownedShare(tx, value(in.ResourceShareArn), "UpdateResourceShare", true)
	if e != nil {
		return nil, e
	}
	if e = checkShareOwner(tx.Context(), v); e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "UpdateResourceShare", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if replay && (in.Name != nil && value(in.Name) != v.Name || in.AllowExternalPrincipals != nil && bool(*in.AllowExternalPrincipals) != v.AllowExternal) {
		return nil, failure("InvalidClientTokenException", v.ARN)
	}
	if !replay {
		if in.Name != nil {
			if strings.TrimSpace(value(in.Name)) == "" || len(value(in.Name)) > 255 {
				return nil, failure("InvalidParameterException", "Invalid resource share name.")
			}
			v.Name = value(in.Name)
		}
		if in.AllowExternalPrincipals != nil {
			v.AllowExternal = bool(*in.AllowExternalPrincipals)
			if !v.AllowExternal {
				if v.RetainOnLeave {
					return nil, failure("InvalidParameterException", "Retained sharing requires external principals.")
				}
				for _, p := range v.Principals {
					if p.Status != "DISASSOCIATED" && !p.Organization {
						return nil, failure("OperationNotPermittedException", "Remove external principals before disabling external sharing.")
					}
				}
			}
		}
		v.Updated = s.clock.Now()
		if e = tx.PutShare(v); e != nil {
			return nil, e
		}
		rec.ARN = v.ARN
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	}
	return &api.UpdateResourceShareResponse{ClientToken: in.ClientToken, ResourceShare: apiShare(v)}, nil
}
func (s *Service) deleteResourceShare(tx Transaction, in *api.DeleteResourceShareRequest) (*api.DeleteResourceShareResponse, error) {
	v, e := s.ownedShare(tx, value(in.ResourceShareArn), "DeleteResourceShare", false)
	if e != nil {
		return nil, e
	}
	if e = checkShareOwner(tx.Context(), v); e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "DeleteResourceShare", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if !replay {
		if v.FeatureSet != "STANDARD" {
			return nil, failure("OperationNotPermittedException", "Policy-created shares must be managed by the resource owner until promoted.")
		}
		for _, r := range v.Resources {
			if r.Status == "ASSOCIATED" {
				if e = s.authorizeResource(tx, r.ARN); e != nil {
					return nil, e
				}
			}
		}
		v.Status = "DELETED"
		v.Updated = s.clock.Now()
		for i := range v.Resources {
			v.Resources[i].Status = "DISASSOCIATED"
			v.Resources[i].Updated = v.Updated
		}
		for i := range v.Principals {
			if e = s.removePrincipal(tx, &v.Principals[i]); e != nil {
				return nil, e
			}
		}
		if e = tx.PutShare(v); e != nil {
			return nil, e
		}
		rec.ARN = v.ARN
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	}
	return &api.DeleteResourceShareResponse{ClientToken: in.ClientToken, ReturnValue: new(api.Boolean(true))}, nil
}
func (s *Service) authorizeResource(r Reader, arn string) error {
	if a, ok := s.resources.(ResourceSharingAuthorizer); ok {
		return a.AuthorizeResourceSharing(r.Context(), arn)
	}
	return nil
}
func (s *Service) resolve(r Reader, arn string) (ResourceIdentity, error) {
	if s.resources == nil {
		return ResourceIdentity{}, ErrUnsupportedResource
	}
	v, e := s.resources.ResolveResource(r.Context(), arn)
	if e != nil {
		return v, e
	}
	if v.ARN != arn || !slices.Contains(s.resourceTypes, v.ResourceType) {
		return ResourceIdentity{}, ErrUnsupportedResource
	}
	return v, nil
}

// addAssociations stamps owner on each edge it creates. Existing live edges keep
// their owner; default permissions are share configuration owned by the share.
func (s *Service) addAssociations(tx Transaction, v *Share, arns api.ResourceArnList, principals api.PrincipalArnOrIdList, owner string) (api.ResourceShareAssociationList, error) {
	if len(arns) > 100 {
		return nil, failure("ResourceShareLimitExceededException", "A call can associate at most 100 resources.")
	}
	now := s.clock.Now()
	for _, arn := range arns {
		r, e := s.resolve(tx, string(arn))
		if e != nil {
			return nil, e
		}
		if r.Partition != v.Partition || r.AccountID != v.AccountID || r.Region != v.Region {
			return nil, failure("OperationNotPermittedException", "Only owned resources in this partition and Region can be shared.")
		}
		if e = s.authorizeResource(tx, r.ARN); e != nil {
			return nil, e
		}
		if r.OrganizationOnly && v.RetainOnLeave {
			return nil, failure("InvalidParameterException", "This resource type cannot retain external sharing.")
		}
		found := false
		for i, a := range v.Resources {
			if a.ARN == r.ARN {
				found = true
				if a.Status != "ASSOCIATED" {
					claim := owner
					if claim == "" && a.Status != "DISASSOCIATED" {
						claim = a.CloudFormationOwner
					}
					v.Resources[i] = ResourceAssociation{ResourceIdentity: r, Status: "ASSOCIATED", Created: now, Updated: now, CloudFormationOwner: claim}
				}
			}
		}
		if !found {
			v.Resources = append(v.Resources, ResourceAssociation{ResourceIdentity: r, Status: "ASSOCIATED", Created: now, Updated: now, CloudFormationOwner: owner})
		}
		hasPermission := false
		for _, p := range v.Permissions {
			if p.ResourceType == r.ResourceType {
				hasPermission = true
			}
		}
		if !hasPermission {
			p, e := s.defaultPermission(tx, r.ResourceType)
			if e != nil {
				return nil, e
			}
			v.Permissions = append(v.Permissions, PermissionAssociation{ARN: p.ARN, ResourceType: p.ResourceType, Version: p.DefaultVersion, CloudFormationOwner: v.CloudFormationOwner})
		}
	}
	for _, principal := range principals {
		p := string(principal)
		idx := slices.IndexFunc(v.Principals, func(a PrincipalAssociation) bool { return a.Principal == p })
		if idx >= 0 {
			status, e := s.principalAssociationStatus(tx, v.Principals[idx])
			if e != nil {
				return nil, e
			}
			if status != "DISASSOCIATED" {
				continue
			}
		}
		a, e := s.newPrincipal(tx, *v, p)
		if e != nil {
			return nil, e
		}
		a.CloudFormationOwner = owner
		if idx >= 0 {
			v.Principals[idx] = a
		} else {
			v.Principals = append(v.Principals, a)
		}
	}
	for i := range v.Resources {
		r := &v.Resources[i]
		if r.Status != "ASSOCIATED" {
			continue
		}
		if len(principals) > 0 && !slices.Contains(arns, api.String(r.ARN)) {
			if e := s.authorizeResource(tx, r.ARN); e != nil {
				return nil, e
			}
		}
		for _, p := range v.Principals {
			if p.Status == "DISASSOCIATED" {
				continue
			}
			if r.OrganizationOnly && !p.Organization {
				return nil, failure("OperationNotPermittedException", "This resource type can be shared only within an enabled organization.")
			}
			if strings.Contains(p.Principal, ":iam:") && !r.SupportsIAMPrincipals {
				return nil, failure("InvalidParameterException", "This resource type does not support IAM principals.")
			}
			if r.ResourceType == "ssm:Parameter" && principalAccount(p.Principal) == v.AccountID {
				r.Status = "FAILED"
				r.StatusMessage = "Resources of specified type cannot be shared with the owning account."
			}
		}
	}
	v.Updated = now
	return selectedAssociations(*v, arns, principals), nil
}
func principalAccount(p string) string {
	if accountPattern.MatchString(p) {
		return p
	}
	parts := strings.SplitN(p, ":", 6)
	if len(parts) == 6 && parts[2] == "iam" && accountPattern.MatchString(parts[4]) && (strings.HasPrefix(parts[5], "role/") || strings.HasPrefix(parts[5], "user/")) {
		return parts[4]
	}
	return ""
}
func (s *Service) newPrincipal(tx Transaction, v Share, p string) (PrincipalAssociation, error) {
	now := s.clock.Now()
	a := PrincipalAssociation{Principal: p, Status: "ASSOCIATED", Created: now, Updated: now}
	account := principalAccount(p)
	if account == "" {
		if !strings.HasPrefix(p, "arn:"+v.Partition+":organizations:") {
			return a, failure("InvalidParameterException", "Principal must identify an account, IAM user or role, organization, or organizational unit.")
		}
		if s.organization == nil {
			return a, failure("OperationNotPermittedException", "Organization sharing is not enabled.")
		}
		ok, e := s.organization.Eligible(tx.Context(), v.AccountID, p, "")
		if e != nil {
			return a, e
		}
		if !ok {
			return a, failure("InvalidParameterException", "The organization principal is not eligible for sharing.")
		}
		a.Organization = true
		return a, nil
	}
	if strings.HasPrefix(p, "arn:") {
		if !strings.HasPrefix(p, "arn:"+v.Partition+":iam:") || s.binder == nil {
			return a, failure("InvalidParameterException", "The IAM principal cannot be resolved.")
		}
		doc, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]string{"AWS": p}, "Action": "ram:GetResourceShares", "Resource": "*"}}})
		bound, e := s.binder.BindResourcePolicy(tx.Context(), string(doc), authorization.ResourcePolicyOptions{})
		if e != nil {
			return a, e
		}
		a.PrincipalID = bound.PrincipalIDs[p]
		if a.PrincipalID == "" {
			return a, failure("InvalidParameterException", "The IAM principal cannot be resolved.")
		}
	}
	eligible := account == v.AccountID
	if !eligible && s.organization != nil {
		var e error
		eligible, e = s.organization.Eligible(tx.Context(), v.AccountID, account, account)
		if e != nil {
			return a, e
		}
	}
	if eligible && !v.RetainOnLeave {
		a.Organization = true
		return a, nil
	}
	if !v.AllowExternal {
		return a, failure("OperationNotPermittedException", "External principals are not allowed.")
	}
	a.Status = "ASSOCIATING"
	invitationScope := v.Scope
	invitationScope.AccountID = account
	a.InvitationARN = arnFor(invitationScope, "resource-share-invitation", identifier())
	i := Invitation{Scope: v.Scope, ARN: a.InvitationARN, ShareARN: v.ARN, ShareName: v.Name, Sender: v.AccountID, Receiver: account, Status: "PENDING", Created: now, Updated: now}
	if e := tx.PutInvitation(i); e != nil {
		return a, e
	}
	return a, nil
}
func (s *Service) associateResourceShare(tx Transaction, in *api.AssociateResourceShareRequest) (*api.AssociateResourceShareResponse, error) {
	v, e := s.ownedShare(tx, value(in.ResourceShareArn), "AssociateResourceShare", true)
	if e != nil {
		return nil, e
	}
	for _, arn := range in.ResourceArns {
		if e = s.claimEdge(tx, v, "RESOURCE", string(arn)); e != nil {
			return nil, e
		}
	}
	for _, principal := range in.Principals {
		if e = s.claimEdge(tx, v, "PRINCIPAL", string(principal)); e != nil {
			return nil, e
		}
	}
	owner, _, e := edgeAuthority(tx.Context(), v)
	if e != nil {
		return nil, e
	}
	if len(in.Sources) > 0 {
		return nil, failure("InvalidParameterException", "These resource owners do not support source constraints.")
	}
	rec, replay, e := receipt(tx, "AssociateResourceShare", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	var out api.ResourceShareAssociationList
	if !replay {
		out, e = s.addAssociations(tx, &v, in.ResourceArns, in.Principals, owner)
		if e != nil {
			return nil, e
		}
		if e = tx.PutShare(v); e != nil {
			return nil, e
		}
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	} else {
		out = selectedAssociations(v, in.ResourceArns, in.Principals)
	}
	return &api.AssociateResourceShareResponse{ClientToken: in.ClientToken, ResourceShareAssociations: out}, nil
}
func resourceAssociation(v Share, r ResourceAssociation, status string) api.ResourceShareAssociation {
	out := apiAssociation(v, r.ARN, "RESOURCE", status, false, r.Created, r.Updated)
	if r.StatusMessage != "" {
		out.StatusMessage = new(api.String(r.StatusMessage))
	}
	return out
}
func selectedAssociations(v Share, arns api.ResourceArnList, principals api.PrincipalArnOrIdList) api.ResourceShareAssociationList {
	out := api.ResourceShareAssociationList{}
	for _, r := range v.Resources {
		if slices.Contains(arns, api.String(r.ARN)) {
			out = append(out, resourceAssociation(v, r, r.Status))
		}
	}
	for _, p := range v.Principals {
		if slices.Contains(principals, api.String(p.Principal)) {
			out = append(out, apiAssociation(v, p.Principal, "PRINCIPAL", p.Status, !p.Organization, p.Created, p.Updated))
		}
	}
	return out
}
func (s *Service) removePrincipal(tx Transaction, p *PrincipalAssociation) error {
	p.Status = "DISASSOCIATED"
	p.CloudFormationOwner = ""
	p.Updated = s.clock.Now()
	if p.InvitationARN != "" {
		i, e := tx.Invitation(p.InvitationARN)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if e == nil {
			i.Status = "REJECTED"
			i.Updated = p.Updated
			return tx.PutInvitation(i)
		}
	}
	return nil
}
func (s *Service) disassociateResourceShare(tx Transaction, in *api.DisassociateResourceShareRequest) (*api.DisassociateResourceShareResponse, error) {
	v, e := s.ownedShare(tx, value(in.ResourceShareArn), "DisassociateResourceShare", true)
	if e != nil {
		return nil, e
	}
	for _, arn := range in.ResourceArns {
		if e = s.claimEdge(tx, v, "RESOURCE", string(arn)); e != nil {
			return nil, e
		}
	}
	for _, principal := range in.Principals {
		if e = s.claimEdge(tx, v, "PRINCIPAL", string(principal)); e != nil {
			return nil, e
		}
	}
	if len(in.Sources) > 0 {
		return nil, failure("InvalidParameterException", "These resource owners do not support source constraints.")
	}
	rec, replay, e := receipt(tx, "DisassociateResourceShare", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if !replay {
		for i := range v.Resources {
			r := &v.Resources[i]
			remove := slices.Contains(in.ResourceArns, api.String(r.ARN))
			if r.Status == "ASSOCIATED" && (remove || len(in.Principals) > 0) {
				if e = s.authorizeResource(tx, r.ARN); e != nil {
					return nil, e
				}
			}
			if remove {
				r.Status = "DISASSOCIATED"
				r.CloudFormationOwner = ""
				r.Updated = s.clock.Now()
			}
		}
		for i := range v.Principals {
			if slices.Contains(in.Principals, api.String(v.Principals[i].Principal)) {
				if e = s.removePrincipal(tx, &v.Principals[i]); e != nil {
					return nil, e
				}
			}
		}
		v.Updated = s.clock.Now()
		if e = tx.PutShare(v); e != nil {
			return nil, e
		}
		if e = saveReceipt(tx, rec); e != nil {
			return nil, e
		}
	}
	return &api.DisassociateResourceShareResponse{ClientToken: in.ClientToken, ResourceShareAssociations: selectedAssociations(v, in.ResourceArns, in.Principals)}, nil
}
func (s *Service) enableSharingWithAwsOrganization(tx Transaction, _ *api.EnableSharingWithAwsOrganizationRequest) (*api.EnableSharingWithAwsOrganizationResponse, error) {
	if e := s.authorize(tx, "EnableSharingWithAwsOrganization", "", nil); e != nil {
		return nil, e
	}
	if s.organization == nil {
		return nil, failure("OperationNotPermittedException", "An Organizations owner is required.")
	}
	ok, e := s.organization.EnableSharing(tx.Context(), scopeFor(tx.Context()).AccountID)
	if e != nil {
		return nil, e
	}
	return &api.EnableSharingWithAwsOrganizationResponse{ReturnValue: new(api.Boolean(ok))}, nil
}
