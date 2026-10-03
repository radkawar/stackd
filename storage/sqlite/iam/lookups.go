package iam

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/iam"
	"stackd/storage/identity"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) Scopes(partition string) ([]domain.Scope, error) {
	rows, err := r.q.Scopes(r.ctx, partition)
	if err != nil {
		return nil, err
	}
	var scopes []domain.Scope
	for _, row := range rows {
		scopes = append(scopes, domain.Scope{Partition: row.Partition, AccountID: row.Account})
	}
	return scopes, nil
}

func (r reader) CredentialReportScopes() ([]domain.Scope, error) {
	rows, err := r.q.CredentialReportScopes(r.ctx)
	if err != nil {
		return nil, err
	}
	var scopes []domain.Scope
	for _, row := range rows {
		scopes = append(scopes, domain.Scope{Partition: row.Partition, AccountID: row.Account})
	}
	return scopes, nil
}

func (r reader) AccessReportScopes() ([]domain.Scope, error) {
	rows, err := r.q.AccessReportScopes(r.ctx)
	if err != nil {
		return nil, err
	}
	var scopes []domain.Scope
	for _, row := range rows {
		scopes = append(scopes, domain.Scope{Partition: row.Partition, AccountID: row.Account})
	}
	return scopes, nil
}

func (r reader) ServiceLinkedRoleDeletionScopes() ([]domain.Scope, error) {
	rows, err := r.q.ServiceLinkedRoleDeletionScopes(r.ctx)
	if err != nil {
		return nil, err
	}
	var scopes []domain.Scope
	for _, row := range rows {
		scopes = append(scopes, domain.Scope{Partition: row.Partition, AccountID: row.Account})
	}
	return scopes, nil
}

func (r reader) AccountAliasOwner(partition, alias string) (string, error) {
	owner, err := r.q.AccountAliasOwner(r.ctx, sqlcgen.AccountAliasOwnerParams{Partition: partition, Alias: alias})
	if errors.Is(err, sql.ErrNoRows) {
		return "", domain.ErrRecordNotFound
	}
	return owner, err
}

func (r reader) PrincipalCredentials(accountID, principalID string) ([]identity.Record, error) {
	keys, err := r.q.ListCredentialKeys(r.ctx, sqlcgen.ListCredentialKeysParams{CredentialAccountID: accountID, CredentialPrincipalID: principalID, CredentialIssuerID: principalID})
	if err != nil {
		return nil, err
	}
	var records []identity.Record
	for _, key := range keys {
		record, err := r.Credential(key)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (r reader) PrincipalActivities(scope domain.Scope) ([]domain.PrincipalActivity, error) {
	keys, err := r.q.ListPrincipalActivityKeys(r.ctx, sqlcgen.ListPrincipalActivityKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.PrincipalActivity
	for _, key := range keys {
		record, err := r.readPrincipalActivity(key.Partition, key.Account, key.KeyPrincipalID, key.KeyServiceNamespace, key.KeyActionName, key.KeyRegion)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (w writer) PutPrincipalActivity(scope domain.Scope, record domain.PrincipalActivity) error {
	previous, err := w.readPrincipalActivity(scope.Partition, scope.AccountID, record.PrincipalID, record.ServiceNamespace, record.ActionName, record.Region)
	if err != nil && !errors.Is(err, domain.ErrRecordNotFound) {
		return err
	}
	if err == nil && previous.LastAuthenticated.After(record.LastAuthenticated) {
		return nil
	}
	if err := w.q.EnsureScope(w.ctx, sqlcgen.EnsureScopeParams{Partition: scope.Partition, Account: scope.AccountID}); err != nil {
		return err
	}
	if _, err := w.q.DeletePrincipalActivity(w.ctx, sqlcgen.DeletePrincipalActivityParams{Partition: scope.Partition, Account: scope.AccountID, KeyPrincipalID: record.PrincipalID, KeyServiceNamespace: record.ServiceNamespace, KeyActionName: record.ActionName, KeyRegion: record.Region}); err != nil {
		return err
	}
	return w.writePrincipalActivity(scope.Partition, scope.AccountID, record.PrincipalID, record.ServiceNamespace, record.ActionName, record.Region, record)
}

func (r reader) PendingAccessReports(scope domain.Scope) ([]domain.AccessReport, error) {
	keys, err := r.q.PendingAccessReportKeys(r.ctx, sqlcgen.PendingAccessReportKeysParams{Partition: scope.Partition, Account: scope.AccountID})
	if err != nil {
		return nil, err
	}
	var records []domain.AccessReport
	for _, key := range keys {
		record, err := r.AccessReport(scope, key)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (r reader) LatestOrganizationAccessReport(scope domain.Scope, owner, entityPath, policyID string) (domain.AccessReport, error) {
	candidates, err := r.q.OrganizationAccessReportCandidates(r.ctx, sqlcgen.OrganizationAccessReportCandidatesParams{Partition: scope.Partition, Account: scope.AccountID, Owner: owner, EntityPath: entityPath, PolicyID: policyID})
	if err != nil {
		return domain.AccessReport{}, err
	}
	var latestID string
	var latestDate time.Time
	found := false
	// Compare typed instants: SQLite's text representation of timestamps need
	// not sort chronologically across time zones or fractional-second widths.
	for _, row := range candidates {
		if !found || row.RequestedAt.After(latestDate) || (row.RequestedAt.Equal(latestDate) && row.ResourceKey > latestID) {
			latestID, latestDate, found = row.ResourceKey, row.RequestedAt, true
		}
	}
	if !found {
		return domain.AccessReport{}, domain.ErrRecordNotFound
	}
	return r.AccessReport(scope, latestID)
}
