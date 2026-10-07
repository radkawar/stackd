package appconfig

import (
	domain "stackd/storage/appconfig"
	"stackd/storage/sqlite/appconfig/internal/sqlcgen"
)

func (r reader) loadExtension(v sqlcgen.AppconfigExtension) (domain.Extension, error) {
	out := domain.Extension{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID, Name: v.Name, Description: v.Description, ARN: v.Arn, Version: int32(v.Version), Ownership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}}
	actions, err := r.q.ListExtensionActions(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, child := range actions {
		item := domain.ExtensionAction{Point: child.Point, Name: child.Name, Description: child.Description, URI: child.Uri, RoleARN: child.RoleArn}
		out.Actions = append(out.Actions, item)
	}
	parameters, err := r.q.ListExtensionParameters(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, child := range parameters {
		item := domain.ExtensionParameter{Name: child.Name, Description: child.Description, Required: child.Required, Dynamic: child.Dynamic}
		out.Parameters = append(out.Parameters, item)
	}
	return out, nil
}
func (r reader) Extensions(s domain.Scope) ([]domain.Extension, error) {
	rows, err := r.q.ListExtensions(r.ctx, sqlcgen.ListExtensionsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Extension, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadExtension(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutExtension(v domain.Extension) error {
	id, err := w.q.PutExtension(w.ctx, sqlcgen.PutExtensionParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Name: v.Name, Description: v.Description, Arn: v.ARN, Version: int64(v.Version), CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token})
	if err != nil {
		return err
	}
	if err = w.q.ClearExtensionActions(w.ctx, id); err != nil {
		return err
	}
	for ordinal, child := range v.Actions {
		err = w.q.InsertExtensionAction(w.ctx, sqlcgen.InsertExtensionActionParams{ParentID: id, Ordinal: int64(ordinal), Point: child.Point, Name: child.Name, Description: child.Description, Uri: child.URI, RoleArn: child.RoleARN})
		if err != nil {
			return err
		}
	}
	if err = w.q.ClearExtensionParameters(w.ctx, id); err != nil {
		return err
	}
	for ordinal, child := range v.Parameters {
		err = w.q.InsertExtensionParameter(w.ctx, sqlcgen.InsertExtensionParameterParams{ParentID: id, Ordinal: int64(ordinal), Name: child.Name, Description: child.Description, Required: child.Required, Dynamic: child.Dynamic})
		if err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteExtension(s domain.Scope, iD string, version int32) error {
	return w.q.DeleteExtension(w.ctx, sqlcgen.DeleteExtensionParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ID: iD, Version: int64(version)})
}

func (r reader) loadAssociation(v sqlcgen.AppconfigAssociation) (domain.Association, error) {
	out := domain.Association{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID, ARN: v.Arn, ExtensionID: v.ExtensionID, ExtensionARN: v.ExtensionArn, ResourceARN: v.ResourceArn, ExtensionVersion: int32(v.ExtensionVersion), Ownership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}}
	parameters, err := r.q.ListAssociationParameters(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	if len(parameters) > 0 {
		out.Parameters = make(map[string]string, len(parameters))
	}
	for _, p := range parameters {
		out.Parameters[p.Name] = p.Value
	}
	return out, nil
}
func (r reader) Associations(s domain.Scope) ([]domain.Association, error) {
	rows, err := r.q.ListAssociations(r.ctx, sqlcgen.ListAssociationsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Association, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadAssociation(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutAssociation(v domain.Association) error {
	id, err := w.q.PutAssociation(w.ctx, sqlcgen.PutAssociationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Arn: v.ARN, ExtensionID: v.ExtensionID, ExtensionArn: v.ExtensionARN, ResourceArn: v.ResourceARN, ExtensionVersion: int64(v.ExtensionVersion), CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token})
	if err != nil {
		return err
	}
	if err = w.q.ClearAssociationParameters(w.ctx, id); err != nil {
		return err
	}
	for name, value := range v.Parameters {
		if err = w.q.InsertAssociationParameter(w.ctx, sqlcgen.InsertAssociationParameterParams{ParentID: id, Name: name, Value: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteAssociation(s domain.Scope, iD string) error {
	return w.q.DeleteAssociation(w.ctx, sqlcgen.DeleteAssociationParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ID: iD})
}
