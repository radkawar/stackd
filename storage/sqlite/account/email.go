package account

import (
	"database/sql"
	"errors"

	domain "stackd/storage/account"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/account/internal/sqlcgen"
)

func (r reader) PrimaryEmailUpdate(sc domain.Scope) (domain.PrimaryEmailUpdate, bool, error) {
	row, err := r.q.GetPrimaryEmailUpdate(r.ctx, sqlcgen.GetPrimaryEmailUpdateParams{Partition: sc.Partition, Account: sc.AccountID})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.PrimaryEmailUpdate{}, false, nil
	}
	if err != nil {
		return domain.PrimaryEmailUpdate{}, false, err
	}
	return emailUpdate(row), true, nil
}

func (r reader) PrimaryEmailUpdates() ([]domain.PrimaryEmailUpdate, error) {
	rows, err := r.q.ListPrimaryEmailUpdates(r.ctx)
	if err != nil {
		return nil, err
	}
	updates := make([]domain.PrimaryEmailUpdate, 0, len(rows))
	for _, row := range rows {
		updates = append(updates, emailUpdate(row))
	}
	return updates, nil
}

func emailUpdate(row sqlcgen.AccountEmailUpdate) domain.PrimaryEmailUpdate {
	return domain.PrimaryEmailUpdate{Scope: domain.Scope{Partition: row.Partition, AccountID: row.Account}, Generation: uint64(row.Generation), Email: row.Email, OTP: row.Otp, Status: domain.PrimaryEmailStatus(row.Status), UpdatedAt: row.UpdatedAt, ExpiresAt: row.ExpiresAt, Due: row.Due, NoticePending: row.NoticePending}
}

func (w writer) PutPrimaryEmailUpdate(record domain.PrimaryEmailUpdate) error {
	return w.q.PutPrimaryEmailUpdate(w.ctx, sqlcgen.PutPrimaryEmailUpdateParams{Partition: record.Scope.Partition, Account: record.Scope.AccountID, Generation: sqlite.Uint64(record.Generation), Email: record.Email, Otp: record.OTP, Status: string(record.Status), UpdatedAt: record.UpdatedAt, ExpiresAt: record.ExpiresAt, Due: record.Due, NoticePending: record.NoticePending})
}
