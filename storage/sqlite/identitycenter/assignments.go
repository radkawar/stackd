package identitycenter

import (
	domain "stackd/storage/identitycenter"
	"stackd/storage/sqlite/identitycenter/internal/sqlcgen"
)

func (r reader) Assignments(instance string) ([]domain.Assignment, error) {
	rows, err := r.q.ListAssignments(r.ctx, instance)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Assignment, len(rows))
	for i, row := range rows {
		out[i] = domain.Assignment{InstanceARN: row.InstanceArn, PermissionSetARN: row.PermissionSetArn, AccountID: row.AccountID, PrincipalType: row.PrincipalType, PrincipalID: row.PrincipalID, CloudFormationOwner: row.CloudformationOwner}
	}
	return out, nil
}

func (w writer) PutAssignment(v domain.Assignment) error {
	return w.q.PutAssignment(w.ctx, sqlcgen.PutAssignmentParams{InstanceArn: v.InstanceARN, PermissionSetArn: v.PermissionSetARN, AccountID: v.AccountID, PrincipalType: v.PrincipalType, PrincipalID: v.PrincipalID, CloudformationOwner: v.CloudFormationOwner})
}

func (w writer) DeleteAssignment(v domain.Assignment) error {
	return w.q.DeleteAssignment(w.ctx, sqlcgen.DeleteAssignmentParams{InstanceArn: v.InstanceARN, PermissionSetArn: v.PermissionSetARN, AccountID: v.AccountID, PrincipalType: v.PrincipalType, PrincipalID: v.PrincipalID})
}

func (r reader) Provisionings(instance string) ([]domain.Provisioning, error) {
	rows, err := r.q.ListProvisionings(r.ctx, instance)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Provisioning, len(rows))
	for i, row := range rows {
		out[i] = domain.Provisioning{InstanceARN: row.InstanceArn, PermissionSetARN: row.PermissionSetArn, AccountID: row.AccountID, RoleARN: row.RoleArn, RoleID: row.RoleID, RoleName: row.RoleName}
	}
	return out, nil
}

func (w writer) PutProvisioning(v domain.Provisioning) error {
	return w.q.PutProvisioning(w.ctx, sqlcgen.PutProvisioningParams{InstanceArn: v.InstanceARN, PermissionSetArn: v.PermissionSetARN, AccountID: v.AccountID, RoleArn: v.RoleARN, RoleID: v.RoleID, RoleName: v.RoleName})
}

func (w writer) DeleteProvisioning(v domain.Provisioning) error {
	return w.q.DeleteProvisioning(w.ctx, sqlcgen.DeleteProvisioningParams{PermissionSetArn: v.PermissionSetARN, AccountID: v.AccountID})
}

func (r reader) Operation(id string) (domain.Operation, error) {
	row, err := r.q.GetOperation(r.ctx, id)
	if err != nil {
		return domain.Operation{}, missing(err)
	}
	return operation(row), nil
}

func (r reader) Operations(instance string) ([]domain.Operation, error) {
	rows, err := r.q.ListOperations(r.ctx, instance)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Operation, len(rows))
	for i, row := range rows {
		out[i] = operation(row)
	}
	return out, nil
}

func operation(row sqlcgen.IdentitycenterOperation) domain.Operation {
	return domain.Operation{InstanceARN: row.InstanceArn, ID: row.ID, Kind: row.Kind, PermissionSetARN: row.PermissionSetArn, AccountID: row.AccountID, PrincipalType: row.PrincipalType, PrincipalID: row.PrincipalID, Created: row.Created.UTC()}
}

func (w writer) PutOperation(v domain.Operation) error {
	return w.q.PutOperation(w.ctx, sqlcgen.PutOperationParams{ID: v.ID, InstanceArn: v.InstanceARN, Kind: v.Kind, PermissionSetArn: v.PermissionSetARN, AccountID: v.AccountID, PrincipalType: v.PrincipalType, PrincipalID: v.PrincipalID, Created: v.Created.UTC()})
}
