package ec2

import (
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) IdentitySigningKey(kind string) (domain.IdentitySigningKeyRecord, error) {
	row, err := r.q.GetIdentitySigningKey(r.ctx, kind)
	if err != nil {
		return domain.IdentitySigningKeyRecord{}, missing(err)
	}
	return domain.IdentitySigningKeyRecord{Kind: row.Kind, PrivateKeyDER: row.PrivateKeyDer, CertificateDER: row.CertificateDer}, nil
}

func (w writer) PutIdentitySigningKey(record domain.IdentitySigningKeyRecord) error {
	return w.q.PutIdentitySigningKey(w.ctx, sqlcgen.PutIdentitySigningKeyParams{Kind: record.Kind, PrivateKeyDer: record.PrivateKeyDER, CertificateDer: record.CertificateDER})
}
