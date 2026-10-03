package kms

import (
	domain "stackd/storage/kms"
	"stackd/storage/sqlite/kms/internal/sqlcgen"
)

func (tx reader) imports(sc domain.StorageScope, key *domain.KeyRecord) error {
	imports, err := tx.q.ListImports(tx.ctx, sqlcgen.ListImportsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID})
	if err != nil {
		return err
	}
	for _, row := range imports {
		key.Imports = append(key.Imports, domain.ImportedMaterialRecord{ID: row.MaterialID, ValidTo: row.ValidTo})
	}
	parameters, err := tx.q.ListImportParameters(tx.ctx, sqlcgen.ListImportParametersParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID})
	if err != nil {
		return err
	}
	for _, row := range parameters {
		key.ImportParameters = append(key.ImportParameters, domain.ImportParametersRecord{Token: row.Token, PrivateKey: row.PrivateKey, Algorithm: row.Algorithm, ValidTo: row.ValidTo})
	}
	return nil
}

func (tx transaction) putImports(sc domain.StorageScope, key domain.KeyRecord) error {
	if err := tx.q.ClearImports(tx.ctx, sqlcgen.ClearImportsParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID}); err != nil {
		return err
	}
	for _, imported := range key.Imports {
		if err := tx.q.InsertImport(tx.ctx, sqlcgen.InsertImportParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID, MaterialID: imported.ID, ValidTo: imported.ValidTo}); err != nil {
			return err
		}
	}
	if err := tx.q.ClearImportParameters(tx.ctx, sqlcgen.ClearImportParametersParams{Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID}); err != nil {
		return err
	}
	for i, parameters := range key.ImportParameters {
		// Expiry clears the private key. The SQL column represents that absence
		// with an empty blob, while the domain permits a nil byte slice.
		privateKey := parameters.PrivateKey
		if privateKey == nil {
			privateKey = []byte{}
		}
		if err := tx.q.InsertImportParameter(tx.ctx, sqlcgen.InsertImportParameterParams{
			Partition: sc.Partition, Account: sc.AccountID, Region: sc.Region, KeyID: key.ID, Position: int64(i), Token: parameters.Token,
			PrivateKey: privateKey, Algorithm: parameters.Algorithm, ValidTo: parameters.ValidTo,
		}); err != nil {
			return err
		}
	}
	return nil
}
