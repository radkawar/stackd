package lambda

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) CodeArchive(key domain.CodeArchiveKey) (domain.CodeArchive, error) {
	v, err := r.q.GetCodeArchive(r.ctx, sqlcgen.GetCodeArchiveParams{Partition: key.Partition, Account: key.Account, Region: key.Region, CodeSha256: key.SHA256})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CodeArchive{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.CodeArchive{}, err
	}
	return domain.CodeArchive{Key: key, Code: v.Code, CreatedAt: v.CreatedAt, RetainUntil: v.RetainUntil}, nil
}

func (r reader) CodeSigningKey(scope domain.Scope) (domain.CodeSigningKey, error) {
	v, err := r.q.GetCodeSigningKey(r.ctx, sqlcgen.GetCodeSigningKeyParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CodeSigningKey{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.CodeSigningKey{}, err
	}
	return domain.CodeSigningKey{Scope: scope, AccessKeyID: v.AccessKeyID, SecretAccessKey: v.SecretAccessKey}, nil
}

func (r reader) NextCodeArchiveDeadline() (time.Time, bool, error) {
	until, err := r.q.NextCodeArchiveDeadline(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return until.Add(time.Nanosecond), true, nil
}

func (w writer) PutCodeArchive(archive domain.CodeArchive) error {
	code := archive.Code
	if code == nil {
		code = []byte{}
	}
	return w.q.PutCodeArchive(w.ctx, sqlcgen.PutCodeArchiveParams{
		Partition: archive.Key.Partition, Account: archive.Key.Account, Region: archive.Key.Region, CodeSha256: archive.Key.SHA256,
		Code: code, CreatedAt: archive.CreatedAt.UTC(), RetainUntil: archive.RetainUntil.UTC(),
	})
}

func (w writer) RetainCodeArchive(key domain.CodeArchiveKey, until time.Time) error {
	updated, err := w.q.RetainCodeArchive(w.ctx, sqlcgen.RetainCodeArchiveParams{
		Partition: key.Partition, Account: key.Account, Region: key.Region, CodeSha256: key.SHA256, RetainUntil: until.UTC(),
	})
	if err == nil && updated == 0 {
		return domain.ErrNotFound
	}
	return err
}

func (w writer) PutCodeSigningKey(key domain.CodeSigningKey) error {
	return w.q.PutCodeSigningKey(w.ctx, sqlcgen.PutCodeSigningKeyParams{
		Partition: key.Partition, Account: key.Account, Region: key.Region,
		AccessKeyID: key.AccessKeyID, SecretAccessKey: key.SecretAccessKey,
	})
}

func (w writer) DeleteExpiredCodeArchives(now time.Time) (int64, error) {
	return w.q.DeleteExpiredCodeArchives(w.ctx, now.UTC())
}
