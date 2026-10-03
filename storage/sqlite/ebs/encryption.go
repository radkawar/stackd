package ebs

import (
	domain "stackd/storage/ebs"
	"stackd/storage/sqlite/ebs/internal/sqlcgen"
)

func (r reader) EncryptionDefault(scope domain.Scope) (domain.EncryptionDefault, error) {
	v, err := r.q.GetEncryptionDefault(r.ctx, sqlcgen.GetEncryptionDefaultParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return domain.EncryptionDefault{}, missing(err)
	}
	return domain.EncryptionDefault{Scope: scope, Enabled: v.Enabled, KMSKeyID: v.KmsKeyID}, nil
}

func (w writer) PutEncryptionDefault(v domain.EncryptionDefault) error {
	return w.q.PutEncryptionDefault(w.ctx, sqlcgen.PutEncryptionDefaultParams{
		Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region,
		Enabled: v.Enabled, KmsKeyID: v.KMSKeyID,
	})
}
