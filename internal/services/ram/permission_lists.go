package ram

import (
	"slices"
	api "stackd/internal/awsapi/ram"
	"stackd/internal/services/identitystore"
	"strconv"
	"strings"
)

func (s *Service) allPermissions(r Reader) ([]Permission, error) {
	rows, e := r.Permissions()
	if e != nil {
		return nil, e
	}
	sc := scopeFor(r.Context())
	out := []Permission{}
	for _, p := range s.managed {
		if !slices.Contains(s.resourceTypes, p.ResourceType) {
			continue
		}
		p.ARN = strings.Replace(p.ARN, "arn:aws:", "arn:"+sc.Partition+":", 1)
		out = append(out, p)
	}
	for _, p := range rows {
		if p.Scope == sc && p.Status != "DELETED" {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b Permission) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func (s *Service) listPermissions(tx Transaction, in *api.ListPermissionsRequest) (*api.ListPermissionsResponse, error) {
	if e := s.authorize(tx, "ListPermissions", "", nil); e != nil {
		return nil, e
	}
	rows, e := s.allPermissions(tx)
	if e != nil {
		return nil, e
	}
	out := api.ResourceSharePermissionList{}
	for _, p := range rows {
		if owner := identitystore.CloudFormationOwner(tx.Context()); owner != "" && p.Type == "CUSTOMER_MANAGED" && owner != p.CloudFormationOwner {
			continue
		}
		if in.ResourceType != nil && !strings.EqualFold(value(in.ResourceType), p.ResourceType) || in.PermissionType != nil && value(in.PermissionType) != "ALL" && value(in.PermissionType) != p.Type {
			continue
		}
		out = append(out, *permissionSummary(p, p.DefaultVersion, "ListPermissions"))
	}
	out, next, e := page(s, tx, "ListPermissions", in, out, in.MaxResults, in.NextToken)
	return &api.ListPermissionsResponse{Permissions: out, NextToken: next}, e
}
func (s *Service) listPermissionVersions(tx Transaction, in *api.ListPermissionVersionsRequest) (*api.ListPermissionVersionsResponse, error) {
	if e := s.authorize(tx, "ListPermissionVersions", value(in.PermissionArn), nil); e != nil {
		return nil, e
	}
	p, e := s.permission(tx, value(in.PermissionArn))
	if e != nil {
		return nil, e
	}
	out := api.ResourceSharePermissionList{}
	for _, v := range p.Versions {
		out = append(out, *permissionSummary(p, v.Version, "ListPermissionVersions"))
	}
	out, next, e := page(s, tx, "ListPermissionVersions", in, out, in.MaxResults, in.NextToken)
	return &api.ListPermissionVersionsResponse{Permissions: out, NextToken: next}, e
}
func (s *Service) readableShare(r Reader, arn, op string) (Share, error) {
	sh, e := r.Share(arn)
	if e != nil {
		return sh, e
	}
	owner := "SELF"
	if sh.AccountID != scopeFor(r.Context()).AccountID {
		owner = "OTHER-ACCOUNTS"
	}
	ok, e := s.visibleShare(r, sh, owner)
	if e != nil {
		return sh, e
	}
	if !ok {
		return Share{}, ErrNotFound
	}
	if e = s.authorize(r, op, sh.ARN, sh.Tags); e != nil {
		return Share{}, e
	}
	return sh, nil
}
func (s *Service) listResourceSharePermissions(tx Transaction, in *api.ListResourceSharePermissionsRequest) (*api.ListResourceSharePermissionsResponse, error) {
	sh, e := s.readableShare(tx, value(in.ResourceShareArn), "ListResourceSharePermissions")
	if e != nil {
		return nil, e
	}
	owner, filtered, e := ownedView(tx.Context(), sh)
	if e != nil {
		return nil, e
	}
	out := api.ResourceSharePermissionList{}
	for _, a := range sh.Permissions {
		if filtered && a.CloudFormationOwner != owner {
			continue
		}
		p, e := s.sharePermission(tx, sh, a)
		if e != nil {
			return nil, e
		}
		v := permissionSummary(p, a.Version, "ListResourceSharePermissions")
		v.Status = new(api.String("ASSOCIATED"))
		out = append(out, *v)
	}
	out, next, e := page(s, tx, "ListResourceSharePermissions", in, out, in.MaxResults, in.NextToken)
	return &api.ListResourceSharePermissionsResponse{Permissions: out, NextToken: next}, e
}
func (s *Service) listPermissionAssociations(tx Transaction, in *api.ListPermissionAssociationsRequest) (*api.ListPermissionAssociationsResponse, error) {
	visible := map[string]bool{}
	if in.PermissionArn != nil {
		p, e := s.permission(tx, value(in.PermissionArn))
		if e != nil {
			return nil, e
		}
		if e = s.authorize(tx, "ListPermissionAssociations", p.ARN, p.Tags); e != nil {
			return nil, e
		}
		visible[p.ARN] = true
	} else {
		permissions, e := s.allPermissions(tx)
		if e != nil {
			return nil, e
		}
		// With no ARN filter, return only associations of currently authorized
		// permissions. A wildcard grant alone cannot hide a per-resource denial.
		for _, p := range permissions {
			if e = s.authorize(tx, "ListPermissionAssociations", p.ARN, p.Tags); e != nil {
				if wireError(e).Code != "AccessDeniedException" {
					return nil, e
				}
				continue
			}
			visible[p.ARN] = true
		}
		if len(visible) == 0 {
			if e = s.authorize(tx, "ListPermissionAssociations", "", nil); e != nil {
				return nil, e
			}
		}
	}
	rows, e := tx.Shares()
	if e != nil {
		return nil, e
	}
	out := api.AssociatedPermissionList{}
	for _, sh := range rows {
		if sh.Scope != scopeFor(tx.Context()) || sh.Status != "ACTIVE" {
			continue
		}
		owner, filtered, e := ownedView(tx.Context(), sh)
		if e != nil {
			return nil, e
		}
		for _, a := range sh.Permissions {
			if !visible[a.ARN] || filtered && a.CloudFormationOwner != owner {
				continue
			}
			p, e := s.sharePermission(tx, sh, a)
			if e != nil {
				return nil, e
			}
			def := a.Version == p.DefaultVersion
			if in.PermissionArn != nil && value(in.PermissionArn) != a.ARN || in.PermissionVersion != nil && int32(*in.PermissionVersion) != a.Version || in.ResourceType != nil && value(in.ResourceType) != a.ResourceType || in.DefaultVersion != nil && bool(*in.DefaultVersion) != def || in.FeatureSet != nil && value(in.FeatureSet) != p.FeatureSet || in.AssociationStatus != nil && value(in.AssociationStatus) != "ASSOCIATED" {
				continue
			}
			out = append(out, api.AssociatedPermission{Arn: new(api.String(a.ARN)), ResourceShareArn: new(api.String(sh.ARN)), ResourceType: new(api.String(a.ResourceType)), PermissionVersion: new(api.String(strconv.Itoa(int(a.Version)))), DefaultVersion: new(api.Boolean(def)), FeatureSet: new(api.PermissionFeatureSet(p.FeatureSet)), Status: new(api.String("ASSOCIATED")), LastUpdatedTime: &sh.Updated})
		}
	}
	out, next, e := page(s, tx, "ListPermissionAssociations", in, out, in.MaxResults, in.NextToken)
	return &api.ListPermissionAssociationsResponse{Permissions: out, NextToken: next}, e
}
func apiReplacement(v Replacement) *api.ReplacePermissionAssociationsWork {
	out := &api.ReplacePermissionAssociationsWork{Id: new(api.String(v.ID)), FromPermissionArn: new(api.String(v.FromARN)), ToPermissionArn: new(api.String(v.ToARN)), ToPermissionVersion: new(api.String(strconv.Itoa(int(v.ToVersion)))), Status: new(api.ReplacePermissionAssociationsWorkStatus(v.Status)), CreationTime: &v.Created, LastUpdatedTime: &v.Updated}
	if v.FromVersion != 0 {
		out.FromPermissionVersion = new(api.String(strconv.Itoa(int(v.FromVersion))))
	}
	return out
}
func (s *Service) replacePermissionAssociations(tx Transaction, in *api.ReplacePermissionAssociationsRequest) (*api.ReplacePermissionAssociationsResponse, error) {
	from, e := s.permission(tx, value(in.FromPermissionArn))
	if e != nil {
		return nil, e
	}
	to, e := s.permission(tx, value(in.ToPermissionArn))
	if e != nil {
		return nil, e
	}
	// Both current definitions remain protected even when replaying a receipt.
	if e = s.authorize(tx, "ReplacePermissionAssociations", from.ARN, from.Tags); e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "ReplacePermissionAssociations", to.ARN, to.Tags); e != nil {
		return nil, e
	}
	rec, replay, e := receipt(tx, "ReplacePermissionAssociations", in.ClientToken, in)
	if e != nil {
		return nil, e
	}
	if replay {
		rows, e := tx.Replacements()
		if e != nil {
			return nil, e
		}
		for _, v := range rows {
			if v.ID == rec.ARN {
				return &api.ReplacePermissionAssociationsResponse{ClientToken: in.ClientToken, ReplacePermissionAssociationsWork: apiReplacement(v)}, nil
			}
		}
		return nil, ErrNotFound
	}
	if from.ResourceType != to.ResourceType || to.Status == "DELETED" || to.FeatureSet != "STANDARD" {
		return nil, failure("InvalidParameterException", "Replacement permission must be attachable and have the same resource type.")
	}
	var version int32
	if in.FromPermissionVersion != nil {
		version = int32(*in.FromPermissionVersion)
		if _, e = versionOf(from, version); e != nil {
			return nil, e
		}
	}
	rows, e := tx.Shares()
	if e != nil {
		return nil, e
	}
	for _, sh := range rows {
		if sh.Scope != scopeFor(tx.Context()) || sh.Status != "ACTIVE" || sh.FeatureSet != "STANDARD" {
			continue
		}
		changed := false
		for n, a := range sh.Permissions {
			if a.ARN == from.ARN && (version == 0 || a.Version == version) {
				for _, r := range sh.Resources {
					if r.ResourceType == a.ResourceType && r.Status == "ASSOCIATED" {
						if e = s.authorizeResource(tx, r.ARN); e != nil {
							return nil, e
						}
					}
				}
				// A direct replacement clears the claim unless the same edge is only upgraded.
				replacement := PermissionAssociation{ARN: to.ARN, ResourceType: to.ResourceType, Version: to.DefaultVersion}
				if to.ARN == a.ARN {
					replacement.CloudFormationOwner = a.CloudFormationOwner
				}
				sh.Permissions[n] = replacement
				changed = true
			}
		}
		if changed {
			sh.Updated = s.clock.Now()
			if e = tx.PutShare(sh); e != nil {
				return nil, e
			}
		}
	}
	now := s.clock.Now()
	work := Replacement{Scope: scopeFor(tx.Context()), ID: identifier(), FromARN: from.ARN, ToARN: to.ARN, FromVersion: version, ToVersion: to.DefaultVersion, Status: "COMPLETED", Created: now, Updated: now}
	if e = tx.PutReplacement(work); e != nil {
		return nil, e
	}
	rec.ARN = work.ID
	if e = saveReceipt(tx, rec); e != nil {
		return nil, e
	}
	return &api.ReplacePermissionAssociationsResponse{ClientToken: in.ClientToken, ReplacePermissionAssociationsWork: apiReplacement(work)}, nil
}
func (s *Service) listReplacePermissionAssociationsWork(tx Transaction, in *api.ListReplacePermissionAssociationsWorkRequest) (*api.ListReplacePermissionAssociationsWorkResponse, error) {
	if e := s.authorize(tx, "ListReplacePermissionAssociationsWork", "", nil); e != nil {
		return nil, e
	}
	rows, e := tx.Replacements()
	if e != nil {
		return nil, e
	}
	out := api.ReplacePermissionAssociationsWorkList{}
	for _, v := range rows {
		if v.Scope != scopeFor(tx.Context()) || in.Status != nil && value(in.Status) != v.Status || len(in.WorkIds) > 0 && !slices.Contains(in.WorkIds, api.String(v.ID)) {
			continue
		}
		out = append(out, *apiReplacement(v))
	}
	out, next, e := page(s, tx, "ListReplacePermissionAssociationsWork", in, out, in.MaxResults, in.NextToken)
	return &api.ListReplacePermissionAssociationsWorkResponse{ReplacePermissionAssociationsWorks: out, NextToken: next}, e
}
