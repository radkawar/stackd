package iam

import (
	"database/sql"
	"errors"

	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) AccessReport(scope domain.Scope, key string) (domain.AccessReport, error) {
	var result domain.AccessReport
	row, err := r.q.GetAccessReport(r.ctx, sqlcgen.GetAccessReportParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: key})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.AccessReport
	record.ID = row.ID
	record.Owner = row.Owner
	record.Granularity = row.Granularity
	record.RequestedAt = row.RequestedAt
	record.CompletedAt = row.CompletedAt
	{
		child, err := r.readAccessReportServices(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Services = child
	}
	{
		child, err := r.readAccessReportOrganization(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Organization = child
	}
	return record, nil
}

func (w writer) PutAccessReport(scope domain.Scope, record domain.AccessReport) error {
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeleteAccessReport(w.ctx, sqlcgen.DeleteAccessReportParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID}); err != nil {
		return err
	}
	if err := w.q.InsertAccessReport(w.ctx, sqlcgen.InsertAccessReportParams{Partition: scope.Partition, Account: scope.AccountID, ResourceKey: record.ID, ID: record.ID, Owner: record.Owner, Granularity: record.Granularity, RequestedAt: record.RequestedAt, CompletedAt: record.CompletedAt}); err != nil {
		return err
	}
	if err := w.writeAccessReportServices(scope.Partition, scope.AccountID, record.ID, record.Services); err != nil {
		return err
	}
	if err := w.writeAccessReportOrganization(scope.Partition, scope.AccountID, record.ID, record.Organization); err != nil {
		return err
	}
	return nil
}

func (r reader) readAccessReportServices(partition string, account string, resourceKey string) ([]domain.ServiceAccess, error) {
	var result []domain.ServiceAccess
	rows, err := r.q.ListAccessReportServices(r.ctx, sqlcgen.ListAccessReportServicesParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.ServiceAccess
		record.Namespace = row.Namespace
		record.Name = row.Name
		{
			child, err := r.readAccessReportServicesLastActivity(row.Partition, row.Account, row.ResourceKey, row.Position1)
			if err != nil {
				return result, err
			}
			record.LastActivity = child
		}
		{
			child, err := r.readAccessReportServicesActions(row.Partition, row.Account, row.ResourceKey, row.Position1)
			if err != nil {
				return result, err
			}
			record.Actions = child
		}
		{
			child, err := r.readAccessReportServicesEntities(row.Partition, row.Account, row.ResourceKey, row.Position1)
			if err != nil {
				return result, err
			}
			record.Entities = child
		}
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readAccessReportServicesLastActivity(partition string, account string, resourceKey string, position1 int64) (*domain.PrincipalActivity, error) {
	var result *domain.PrincipalActivity
	row, err := r.q.GetAccessReportServicesLastActivity(r.ctx, sqlcgen.GetAccessReportServicesLastActivityParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.PrincipalActivity{}
	record.PrincipalID = row.PrincipalID
	record.PrincipalARN = row.PrincipalArn
	record.ServiceNamespace = row.ServiceNamespace
	record.ActionName = row.ActionName
	record.Region = row.Region
	record.LastAuthenticated = row.LastAuthenticated
	return record, nil
}

func (r reader) readAccessReportServicesActions(partition string, account string, resourceKey string, position1 int64) ([]domain.ActionAccess, error) {
	var result []domain.ActionAccess
	rows, err := r.q.ListAccessReportServicesActions(r.ctx, sqlcgen.ListAccessReportServicesActionsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.ActionAccess
		record.Name = row.Name
		{
			child, err := r.readAccessReportServicesActionsLastActivity(row.Partition, row.Account, row.ResourceKey, row.Position1, row.Position2)
			if err != nil {
				return result, err
			}
			record.LastActivity = child
		}
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readAccessReportServicesActionsLastActivity(partition string, account string, resourceKey string, position1 int64, position2 int64) (*domain.PrincipalActivity, error) {
	var result *domain.PrincipalActivity
	row, err := r.q.GetAccessReportServicesActionsLastActivity(r.ctx, sqlcgen.GetAccessReportServicesActionsLastActivityParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, Position2: position2})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.PrincipalActivity{}
	record.PrincipalID = row.PrincipalID
	record.PrincipalARN = row.PrincipalArn
	record.ServiceNamespace = row.ServiceNamespace
	record.ActionName = row.ActionName
	record.Region = row.Region
	record.LastAuthenticated = row.LastAuthenticated
	return record, nil
}

func (r reader) readAccessReportServicesEntities(partition string, account string, resourceKey string, position1 int64) ([]domain.EntityAccess, error) {
	var result []domain.EntityAccess
	rows, err := r.q.ListAccessReportServicesEntities(r.ctx, sqlcgen.ListAccessReportServicesEntitiesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.EntityAccess
		record.ID = row.ID
		{
			child, err := r.readAccessReportServicesEntitiesLastActivity(row.Partition, row.Account, row.ResourceKey, row.Position1, row.Position2)
			if err != nil {
				return result, err
			}
			record.LastActivity = child
		}
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readAccessReportServicesEntitiesLastActivity(partition string, account string, resourceKey string, position1 int64, position2 int64) (*domain.PrincipalActivity, error) {
	var result *domain.PrincipalActivity
	row, err := r.q.GetAccessReportServicesEntitiesLastActivity(r.ctx, sqlcgen.GetAccessReportServicesEntitiesLastActivityParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, Position2: position2})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.PrincipalActivity{}
	record.PrincipalID = row.PrincipalID
	record.PrincipalARN = row.PrincipalArn
	record.ServiceNamespace = row.ServiceNamespace
	record.ActionName = row.ActionName
	record.Region = row.Region
	record.LastAuthenticated = row.LastAuthenticated
	return record, nil
}

func (r reader) readAccessReportOrganization(partition string, account string, resourceKey string) (*domain.OrganizationAccessReport, error) {
	var result *domain.OrganizationAccessReport
	row, err := r.q.GetAccessReportOrganization(r.ctx, sqlcgen.GetAccessReportOrganizationParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.OrganizationAccessReport{}
	record.EntityPath = row.EntityPath
	record.PolicyID = row.PolicyID
	{
		child, err := r.readAccessReportOrganizationServices(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Services = child
	}
	{
		child, err := r.readAccessReportOrganizationError(row.Partition, row.Account, row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Error = child
	}
	return record, nil
}

func (r reader) readAccessReportOrganizationServices(partition string, account string, resourceKey string) ([]domain.OrganizationServiceAccess, error) {
	var result []domain.OrganizationServiceAccess
	rows, err := r.q.ListAccessReportOrganizationServices(r.ctx, sqlcgen.ListAccessReportOrganizationServicesParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		var record domain.OrganizationServiceAccess
		record.Namespace = row.Namespace
		record.Name = row.Name
		record.AuthenticatedAccounts = int(row.AuthenticatedAccounts)
		{
			child, err := r.readAccessReportOrganizationServicesLastActivity(row.Partition, row.Account, row.ResourceKey, row.Position2)
			if err != nil {
				return result, err
			}
			record.LastActivity = child
		}
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readAccessReportOrganizationServicesLastActivity(partition string, account string, resourceKey string, position2 int64) (*domain.AccountActivity, error) {
	var result *domain.AccountActivity
	row, err := r.q.GetAccessReportOrganizationServicesLastActivity(r.ctx, sqlcgen.GetAccessReportOrganizationServicesLastActivityParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position2: position2})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.AccountActivity{}
	record.EntityPath = row.EntityPath
	record.Region = row.Region
	record.LastAuthenticated = row.LastAuthenticated
	return record, nil
}

func (r reader) readAccessReportOrganizationError(partition string, account string, resourceKey string) (*domain.AccessReportError, error) {
	var result *domain.AccessReportError
	row, err := r.q.GetAccessReportOrganizationError(r.ctx, sqlcgen.GetAccessReportOrganizationErrorParams{Partition: partition, Account: account, ResourceKey: resourceKey})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return result, err
	}
	record := &domain.AccessReportError{}
	record.Code = row.Code
	record.Message = row.Message
	return record, nil
}

func (w writer) writeAccessReportServices(partition string, account string, resourceKey string, value []domain.ServiceAccess) error {
	for position1, record := range value {
		if err := w.q.InsertAccessReportServices(w.ctx, sqlcgen.InsertAccessReportServicesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: int64(position1), Namespace: record.Namespace, Name: record.Name}); err != nil {
			return err
		}
		if err := w.writeAccessReportServicesLastActivity(partition, account, resourceKey, int64(position1), record.LastActivity); err != nil {
			return err
		}
		if err := w.writeAccessReportServicesActions(partition, account, resourceKey, int64(position1), record.Actions); err != nil {
			return err
		}
		if err := w.writeAccessReportServicesEntities(partition, account, resourceKey, int64(position1), record.Entities); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeAccessReportServicesLastActivity(partition string, account string, resourceKey string, position1 int64, record *domain.PrincipalActivity) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccessReportServicesLastActivity(w.ctx, sqlcgen.InsertAccessReportServicesLastActivityParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, PrincipalID: record.PrincipalID, PrincipalArn: record.PrincipalARN, ServiceNamespace: record.ServiceNamespace, ActionName: record.ActionName, Region: record.Region, LastAuthenticated: record.LastAuthenticated}); err != nil {
		return err
	}
	return nil
}

func (w writer) writeAccessReportServicesActions(partition string, account string, resourceKey string, position1 int64, value []domain.ActionAccess) error {
	for position2, record := range value {
		if err := w.q.InsertAccessReportServicesActions(w.ctx, sqlcgen.InsertAccessReportServicesActionsParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, Position2: int64(position2), Name: record.Name}); err != nil {
			return err
		}
		if err := w.writeAccessReportServicesActionsLastActivity(partition, account, resourceKey, position1, int64(position2), record.LastActivity); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeAccessReportServicesActionsLastActivity(partition string, account string, resourceKey string, position1 int64, position2 int64, record *domain.PrincipalActivity) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccessReportServicesActionsLastActivity(w.ctx, sqlcgen.InsertAccessReportServicesActionsLastActivityParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, Position2: position2, PrincipalID: record.PrincipalID, PrincipalArn: record.PrincipalARN, ServiceNamespace: record.ServiceNamespace, ActionName: record.ActionName, Region: record.Region, LastAuthenticated: record.LastAuthenticated}); err != nil {
		return err
	}
	return nil
}

func (w writer) writeAccessReportServicesEntities(partition string, account string, resourceKey string, position1 int64, value []domain.EntityAccess) error {
	for position2, record := range value {
		if err := w.q.InsertAccessReportServicesEntities(w.ctx, sqlcgen.InsertAccessReportServicesEntitiesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, Position2: int64(position2), ID: record.ID}); err != nil {
			return err
		}
		if err := w.writeAccessReportServicesEntitiesLastActivity(partition, account, resourceKey, position1, int64(position2), record.LastActivity); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeAccessReportServicesEntitiesLastActivity(partition string, account string, resourceKey string, position1 int64, position2 int64, record *domain.PrincipalActivity) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccessReportServicesEntitiesLastActivity(w.ctx, sqlcgen.InsertAccessReportServicesEntitiesLastActivityParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position1: position1, Position2: position2, PrincipalID: record.PrincipalID, PrincipalArn: record.PrincipalARN, ServiceNamespace: record.ServiceNamespace, ActionName: record.ActionName, Region: record.Region, LastAuthenticated: record.LastAuthenticated}); err != nil {
		return err
	}
	return nil
}

func (w writer) writeAccessReportOrganization(partition string, account string, resourceKey string, record *domain.OrganizationAccessReport) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccessReportOrganization(w.ctx, sqlcgen.InsertAccessReportOrganizationParams{Partition: partition, Account: account, ResourceKey: resourceKey, EntityPath: record.EntityPath, PolicyID: record.PolicyID}); err != nil {
		return err
	}
	if err := w.writeAccessReportOrganizationServices(partition, account, resourceKey, record.Services); err != nil {
		return err
	}
	if err := w.writeAccessReportOrganizationError(partition, account, resourceKey, record.Error); err != nil {
		return err
	}
	return nil
}

func (w writer) writeAccessReportOrganizationServices(partition string, account string, resourceKey string, value []domain.OrganizationServiceAccess) error {
	for position2, record := range value {
		if err := w.q.InsertAccessReportOrganizationServices(w.ctx, sqlcgen.InsertAccessReportOrganizationServicesParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position2: int64(position2), Namespace: record.Namespace, Name: record.Name, AuthenticatedAccounts: int64(record.AuthenticatedAccounts)}); err != nil {
			return err
		}
		if err := w.writeAccessReportOrganizationServicesLastActivity(partition, account, resourceKey, int64(position2), record.LastActivity); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeAccessReportOrganizationServicesLastActivity(partition string, account string, resourceKey string, position2 int64, record *domain.AccountActivity) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccessReportOrganizationServicesLastActivity(w.ctx, sqlcgen.InsertAccessReportOrganizationServicesLastActivityParams{Partition: partition, Account: account, ResourceKey: resourceKey, Position2: position2, EntityPath: record.EntityPath, Region: record.Region, LastAuthenticated: record.LastAuthenticated}); err != nil {
		return err
	}
	return nil
}

func (w writer) writeAccessReportOrganizationError(partition string, account string, resourceKey string, record *domain.AccessReportError) error {
	if record == nil {
		return nil
	}
	if err := w.q.InsertAccessReportOrganizationError(w.ctx, sqlcgen.InsertAccessReportOrganizationErrorParams{Partition: partition, Account: account, ResourceKey: resourceKey, Code: record.Code, Message: record.Message}); err != nil {
		return err
	}
	return nil
}
