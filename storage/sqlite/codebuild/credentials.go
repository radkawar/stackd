package codebuild

import (
	domain "stackd/storage/codebuild"
	"stackd/storage/sqlite/codebuild/internal/sqlcgen"
)

func credential(row sqlcgen.CodebuildCredential) domain.CredentialRecord {
	return domain.CredentialRecord{
		Key: domain.CredentialKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ServerType: row.ServerType, AuthType: row.AuthType},
		ARN: row.Arn, Ciphertext: row.Ciphertext,
		Ownership: row.Ownership,
	}
}

func (r reader) Credential(k domain.CredentialKey) (domain.CredentialRecord, error) {
	row, err := r.q.GetCredential(r.ctx, sqlcgen.GetCredentialParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ServerType: k.ServerType, AuthType: k.AuthType})
	if err != nil {
		return domain.CredentialRecord{}, missing(err)
	}
	return credential(row), nil
}

func (r reader) Credentials(k domain.Scope) ([]domain.CredentialRecord, error) {
	rows, err := r.q.ListCredentials(r.ctx, sqlcgen.ListCredentialsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.CredentialRecord, len(rows))
	for i, row := range rows {
		out[i] = credential(row)
	}
	return out, nil
}

func (w writer) PutCredential(v domain.CredentialRecord) error {
	k := v.Key
	return w.q.PutCredential(w.ctx, sqlcgen.PutCredentialParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ServerType: k.ServerType, AuthType: k.AuthType, Arn: v.ARN, Ciphertext: v.Ciphertext, Ownership: v.Ownership})
}

func (w writer) DeleteCredential(k domain.CredentialKey) error {
	return w.q.DeleteCredential(w.ctx, sqlcgen.DeleteCredentialParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ServerType: k.ServerType, AuthType: k.AuthType})
}
