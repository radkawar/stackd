package ec2

import (
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) LaunchTemplate(k domain.ResourceKey) (domain.LaunchTemplateRecord, error) {
	row, err := r.q.GetLTTemplate(r.ctx, sqlcgen.GetLTTemplateParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return domain.LaunchTemplateRecord{}, missing(err)
	}
	return r.launchTemplate(row)
}
func (r reader) LaunchTemplates(scope domain.Scope) ([]domain.LaunchTemplateRecord, error) {
	rows, err := r.q.ListLTTemplate(r.ctx, sqlcgen.ListLTTemplateParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.LaunchTemplateRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.launchTemplate(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) launchTemplate(row sqlcgen.Ec2LaunchTemplate) (domain.LaunchTemplateRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	out := domain.LaunchTemplateRecord{Key: k, LastVersion: row.LastVersion, Data: api.LaunchTemplate{LaunchTemplateId: new(api.String(k.ID)), LaunchTemplateName: new(api.LaunchTemplateName(row.Name)), CreateTime: new(api.DateTime(row.CreatedAt)), CreatedBy: new(api.String(row.CreatedBy)), DefaultVersionNumber: new(api.Long(row.DefaultVersion)), LatestVersionNumber: new(api.Long(row.LatestVersion)), Operator: &api.OperatorResponse{Managed: new(api.Boolean(false))}}}
	out.CloudFormationOwner = cloudFormationOwner(row.CloudformationResourceType, row.CloudformationOwner)
	if row.TagsPresent {
		tags, err := r.q.ListLTTemplateTag(r.ctx, sqlcgen.ListLTTemplateTagParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID})
		if err != nil {
			return out, err
		}
		out.Data.Tags = make(api.TagList, len(tags))
		for i, tag := range tags {
			out.Data.Tags[i] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
		}
	}
	return out, nil
}
func (w writer) PutLaunchTemplate(v domain.LaunchTemplateRecord) error {
	k, d := v.Key, v.Data
	if err := w.q.PutLTTemplate(w.ctx, sqlcgen.PutLTTemplateParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Name: string(*d.LaunchTemplateName), CreatedAt: *d.CreateTime, CreatedBy: string(*d.CreatedBy), DefaultVersion: int64(*d.DefaultVersionNumber), LatestVersion: int64(*d.LatestVersionNumber), LastVersion: v.LastVersion, TagsPresent: d.Tags != nil}); err != nil {
		return err
	}
	if err := w.q.ClearLTTemplateTag(w.ctx, sqlcgen.ClearLTTemplateTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, t := range d.Tags {
		if err := w.q.PutLTTemplateTag(w.ctx, sqlcgen.PutLTTemplateTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(t.Key), Value: nullableString(t.Value)}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteLaunchTemplate(k domain.ResourceKey) error {
	return deleted(w.q.DeleteLTTemplate(w.ctx, sqlcgen.DeleteLTTemplateParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}))
}
func (r reader) LaunchTemplateVersion(key domain.LaunchTemplateVersionKey) (domain.LaunchTemplateVersionRecord, error) {
	k := key.Template
	row, err := r.q.GetLTVersion(r.ctx, sqlcgen.GetLTVersionParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Version: key.Number})
	if err != nil {
		return domain.LaunchTemplateVersionRecord{}, missing(err)
	}
	return r.launchTemplateVersion(row)
}
func (r reader) LaunchTemplateVersions(k domain.ResourceKey) ([]domain.LaunchTemplateVersionRecord, error) {
	rows, err := r.q.ListLTVersion(r.ctx, sqlcgen.ListLTVersionParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.LaunchTemplateVersionRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.launchTemplateVersion(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) launchTemplateVersion(row sqlcgen.Ec2LtVersionRecord) (domain.LaunchTemplateVersionRecord, error) {
	k := domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID}
	data, err := r.readLTVersion(row)
	return domain.LaunchTemplateVersionRecord{Key: domain.LaunchTemplateVersionKey{Template: k, Number: row.Version}, CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy, Description: stringPointer[api.VersionDescription](row.Description), Data: data}, err
}
func (w writer) PutLaunchTemplateVersion(v domain.LaunchTemplateVersionRecord) error {
	k := v.Key.Template
	return w.writeLTVersion(sqlcgen.PutLTVersionParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Version: v.Key.Number, CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy, Description: nullableString(v.Description)}, v.Data)
}
func (w writer) DeleteLaunchTemplateVersion(key domain.LaunchTemplateVersionKey) error {
	k := key.Template
	return deleted(w.q.DeleteLTVersion(w.ctx, sqlcgen.DeleteLTVersionParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Version: key.Number}))
}
func (r reader) LaunchTemplateToken(k domain.LaunchTemplateTokenKey) (domain.LaunchTemplateTokenRecord, error) {
	row, err := r.q.GetLTToken(r.ctx, sqlcgen.GetLTTokenParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Action: k.Action, Token: k.Token})
	return domain.LaunchTemplateTokenRecord{Key: k, Fingerprint: row.Fingerprint, TemplateID: row.ResourceID, Version: row.Version}, missing(err)
}
func (w writer) PutLaunchTemplateToken(v domain.LaunchTemplateTokenRecord) error {
	k := v.Key
	return w.q.PutLTToken(w.ctx, sqlcgen.PutLTTokenParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, Action: k.Action, Token: k.Token, Fingerprint: v.Fingerprint, ResourceID: v.TemplateID, Version: v.Version})
}
