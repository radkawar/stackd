package ram

import (
	domain "stackd/storage/ram"
	"stackd/storage/sqlite/ram/internal/sqlcgen"
)

func (r reader) Permission(arn string) (domain.Permission, error) {
	row, e := r.q.GetPermission(r.ctx, arn)
	if e != nil {
		return domain.Permission{}, missing(e)
	}
	return r.permission(row)
}
func (r reader) Permissions() ([]domain.Permission, error) {
	rows, e := r.q.ListPermissions(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Permission, 0, len(rows))
	for _, row := range rows {
		v, e := r.permission(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) permission(row sqlcgen.RamPermission) (domain.Permission, error) {
	v := domain.Permission{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ARN: row.Arn, Name: row.Name, ResourceType: row.ResourceType, Type: row.Type, FeatureSet: row.FeatureSet, Status: row.Status, ResourceTypeDefault: row.ResourceTypeDefault, DefaultVersion: int32(row.DefaultVersion), Created: row.Created, Updated: row.Updated, Tags: map[string]string{}, CloudFormationOwner: row.CloudformationOwner, ObjectID: row.ObjectID}
	tags, e := r.q.ListPermissionTags(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, t := range tags {
		v.Tags[t.Key] = t.Value
	}
	rows, e := r.q.ListPermissionVersions(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	actions, e := r.q.ListPermissionActions(r.ctx, v.ARN)
	if e != nil {
		return v, e
	}
	for _, row := range rows {
		version := domain.PermissionVersion{Version: int32(row.Version), Document: row.Document, Created: row.Created, Updated: row.Updated, Deleted: row.Deleted}
		for _, a := range actions {
			if a.Version == row.Version {
				version.Actions = append(version.Actions, a.Action)
			}
		}
		v.Versions = append(v.Versions, version)
	}
	return v, nil
}
func (w writer) PutPermission(v domain.Permission) error {
	if e := w.q.PutPermission(w.ctx, sqlcgen.PutPermissionParams{Arn: v.ARN, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Name: v.Name, ResourceType: v.ResourceType, Type: v.Type, FeatureSet: v.FeatureSet, Status: v.Status, ResourceTypeDefault: v.ResourceTypeDefault, DefaultVersion: int64(v.DefaultVersion), Created: v.Created, Updated: v.Updated, CloudformationOwner: v.CloudFormationOwner, ObjectID: v.ObjectID}); e != nil {
		return e
	}
	if e := w.q.DeletePermissionTags(w.ctx, v.ARN); e != nil {
		return e
	}
	for k, value := range v.Tags {
		if e := w.q.PutPermissionTag(w.ctx, sqlcgen.PutPermissionTagParams{PermissionArn: v.ARN, Key: k, Value: value}); e != nil {
			return e
		}
	}
	if e := w.q.DeletePermissionVersions(w.ctx, v.ARN); e != nil {
		return e
	}
	for _, pv := range v.Versions {
		if e := w.q.PutPermissionVersion(w.ctx, sqlcgen.PutPermissionVersionParams{PermissionArn: v.ARN, Version: int64(pv.Version), Document: pv.Document, Created: pv.Created, Updated: pv.Updated, Deleted: pv.Deleted}); e != nil {
			return e
		}
		for n, a := range pv.Actions {
			if e := w.q.PutPermissionAction(w.ctx, sqlcgen.PutPermissionActionParams{PermissionArn: v.ARN, Version: int64(pv.Version), Position: int64(n), Action: a}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (w writer) DeletePermission(arn string) error { return w.q.DeletePermission(w.ctx, arn) }
func (r reader) Receipt(sc domain.Scope, op, token string) (domain.Receipt, error) {
	v, e := r.q.GetReceipt(r.ctx, sqlcgen.GetReceiptParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Operation: op, Token: token})
	if e != nil {
		return domain.Receipt{}, missing(e)
	}
	return domain.Receipt{Scope: sc, Operation: v.Operation, Token: v.Token, Hash: v.Hash, ARN: v.Arn, Version: int32(v.Version), CloudFormationOwner: v.CloudformationOwner, ObjectID: v.ObjectID}, nil
}
func (w writer) PutReceipt(v domain.Receipt) error {
	return w.q.PutReceipt(w.ctx, sqlcgen.PutReceiptParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Operation: v.Operation, Token: v.Token, Hash: v.Hash, Arn: v.ARN, Version: int64(v.Version), CloudformationOwner: v.CloudFormationOwner, ObjectID: v.ObjectID})
}
func (r reader) Replacements() ([]domain.Replacement, error) {
	rows, e := r.q.ListReplacements(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Replacement, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.Replacement{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID, FromARN: v.FromArn, ToARN: v.ToArn, Status: v.Status, FromVersion: int32(v.FromVersion), ToVersion: int32(v.ToVersion), Created: v.Created, Updated: v.Updated})
	}
	return out, nil
}
func (w writer) PutReplacement(v domain.Replacement) error {
	return w.q.PutReplacement(w.ctx, sqlcgen.PutReplacementParams{ID: v.ID, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, FromArn: v.FromARN, ToArn: v.ToARN, Status: v.Status, FromVersion: int64(v.FromVersion), ToVersion: int64(v.ToVersion), Created: v.Created, Updated: v.Updated})
}
