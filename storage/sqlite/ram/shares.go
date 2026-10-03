package ram

import (
	domain "stackd/storage/ram"
	"stackd/storage/sqlite/ram/internal/sqlcgen"
)

func (r reader) Share(arn string) (domain.Share, error) {
	row, e := r.q.GetShare(r.ctx, arn)
	if e != nil {
		return domain.Share{}, missing(e)
	}
	return r.share(row)
}
func (r reader) Shares() ([]domain.Share, error) {
	rows, e := r.q.ListShares(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Share, 0, len(rows))
	for _, row := range rows {
		v, e := r.share(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) share(row sqlcgen.RamShare) (domain.Share, error) {
	v := domain.Share{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, Name: row.Name, Status: row.Status, FeatureSet: row.FeatureSet, PolicyID: row.PolicyID, AllowExternal: row.AllowExternal, RetainOnLeave: row.RetainOnLeave, Created: row.Created, Updated: row.Updated, Tags: map[string]string{}}
	tags, e := r.q.ListShareTags(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, t := range tags {
		v.Tags[t.Key] = t.Value
	}
	resources, e := r.q.ListResources(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, a := range resources {
		v.Resources = append(v.Resources, domain.ResourceAssociation{ResourceIdentity: domain.ResourceIdentity{ARN: a.Arn, ResourceType: a.ResourceType, Partition: a.Partition, AccountID: a.AccountID, Region: a.Region, OrganizationOnly: a.OrganizationOnly, SupportsIAMPrincipals: a.SupportsIamPrincipals}, Status: a.Status, StatusMessage: a.StatusMessage, Created: a.Created, Updated: a.Updated})
	}
	principals, e := r.q.ListPrincipals(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, a := range principals {
		v.Principals = append(v.Principals, domain.PrincipalAssociation{Principal: a.Principal, PrincipalID: a.PrincipalID, Status: a.Status, InvitationARN: a.InvitationArn, Organization: a.Organization, Created: a.Created, Updated: a.Updated})
	}
	permissions, e := r.q.ListSharePermissions(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, a := range permissions {
		v.Permissions = append(v.Permissions, domain.PermissionAssociation{ARN: a.Arn, ResourceType: a.ResourceType, Version: int32(a.Version)})
	}
	return v, nil
}
func (w writer) PutShare(v domain.Share) error {
	if e := w.q.PutShare(w.ctx, sqlcgen.PutShareParams{Arn: v.ARN, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Name: v.Name, Status: v.Status, FeatureSet: v.FeatureSet, PolicyID: v.PolicyID, AllowExternal: v.AllowExternal, RetainOnLeave: v.RetainOnLeave, Created: v.Created, Updated: v.Updated}); e != nil {
		return e
	}
	if e := w.q.DeleteShareTags(w.ctx, v.ARN); e != nil {
		return e
	}
	for k, value := range v.Tags {
		if e := w.q.PutShareTag(w.ctx, sqlcgen.PutShareTagParams{ShareArn: v.ARN, Key: k, Value: value}); e != nil {
			return e
		}
	}
	if e := w.q.DeleteResources(w.ctx, v.ARN); e != nil {
		return e
	}
	for n, a := range v.Resources {
		if e := w.q.PutResource(w.ctx, sqlcgen.PutResourceParams{ShareArn: v.ARN, Position: int64(n), Arn: a.ARN, ResourceType: a.ResourceType, Partition: a.Partition, AccountID: a.AccountID, Region: a.Region, OrganizationOnly: a.OrganizationOnly, SupportsIamPrincipals: a.SupportsIAMPrincipals, Status: a.Status, StatusMessage: a.StatusMessage, Created: a.Created, Updated: a.Updated}); e != nil {
			return e
		}
	}
	if e := w.q.DeletePrincipals(w.ctx, v.ARN); e != nil {
		return e
	}
	for n, a := range v.Principals {
		if e := w.q.PutPrincipal(w.ctx, sqlcgen.PutPrincipalParams{ShareArn: v.ARN, Position: int64(n), Principal: a.Principal, PrincipalID: a.PrincipalID, Status: a.Status, InvitationArn: a.InvitationARN, Organization: a.Organization, Created: a.Created, Updated: a.Updated}); e != nil {
			return e
		}
	}
	if e := w.q.DeleteSharePermissions(w.ctx, v.ARN); e != nil {
		return e
	}
	for n, a := range v.Permissions {
		if e := w.q.PutSharePermission(w.ctx, sqlcgen.PutSharePermissionParams{ShareArn: v.ARN, Position: int64(n), Arn: a.ARN, ResourceType: a.ResourceType, Version: int64(a.Version)}); e != nil {
			return e
		}
	}
	return nil
}
func invitation(row sqlcgen.RamInvitation) domain.Invitation {
	return domain.Invitation{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, ShareARN: row.ShareArn, ShareName: row.ShareName, Sender: row.Sender, Receiver: row.Receiver, Status: row.Status, Created: row.Created, Updated: row.Updated}
}
func (r reader) Invitation(arn string) (domain.Invitation, error) {
	row, e := r.q.GetInvitation(r.ctx, arn)
	return invitation(row), missing(e)
}
func (r reader) Invitations() ([]domain.Invitation, error) {
	rows, e := r.q.ListInvitations(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Invitation, 0, len(rows))
	for _, row := range rows {
		out = append(out, invitation(row))
	}
	return out, nil
}
func (w writer) PutInvitation(v domain.Invitation) error {
	return w.q.PutInvitation(w.ctx, sqlcgen.PutInvitationParams{Arn: v.ARN, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ShareArn: v.ShareARN, ShareName: v.ShareName, Sender: v.Sender, Receiver: v.Receiver, Status: v.Status, Created: v.Created, Updated: v.Updated})
}
