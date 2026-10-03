package iam

import (
	"database/sql"
	"errors"
	domain "stackd/storage/iam"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) readPrincipalActivity(partition string, account string, keyPrincipalID string, keyServiceNamespace string, keyActionName string, keyRegion string) (domain.PrincipalActivity, error) {
	var result domain.PrincipalActivity
	row, err := r.q.GetPrincipalActivity(r.ctx, sqlcgen.GetPrincipalActivityParams{Partition: partition, Account: account, KeyPrincipalID: keyPrincipalID, KeyServiceNamespace: keyServiceNamespace, KeyActionName: keyActionName, KeyRegion: keyRegion})
	if errors.Is(err, sql.ErrNoRows) {
		return result, domain.ErrRecordNotFound
	}
	if err != nil {
		return result, err
	}
	var record domain.PrincipalActivity
	record.PrincipalID = row.PrincipalID
	record.PrincipalARN = row.PrincipalArn
	record.ServiceNamespace = row.ServiceNamespace
	record.ActionName = row.ActionName
	record.Region = row.Region
	record.LastAuthenticated = row.LastAuthenticated
	result = record
	return result, nil
}

func (w writer) writePrincipalActivity(partition string, account string, keyPrincipalID string, keyServiceNamespace string, keyActionName string, keyRegion string, value domain.PrincipalActivity) error {
	record := value
	if err := w.q.InsertPrincipalActivity(w.ctx, sqlcgen.InsertPrincipalActivityParams{Partition: partition, Account: account, KeyPrincipalID: keyPrincipalID, KeyServiceNamespace: keyServiceNamespace, KeyActionName: keyActionName, KeyRegion: keyRegion, PrincipalID: record.PrincipalID, PrincipalArn: record.PrincipalARN, ServiceNamespace: record.ServiceNamespace, ActionName: record.ActionName, Region: record.Region, LastAuthenticated: record.LastAuthenticated}); err != nil {
		return err
	}
	return nil
}
