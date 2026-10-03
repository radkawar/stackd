// Package cloudcontrol retains request intent in the shared SQLite domain.
package cloudcontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	domain "stackd/storage/cloudcontrol"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/cloudcontrol/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func decode(row sqlcgen.CloudcontrolRequest) (domain.RequestRecord, error) {
	out := domain.RequestRecord{Scope: domain.Scope{Partition: row.Partition, Account: row.AccountID, Region: row.Region}, Token: row.Token, ClientToken: row.ClientToken, RequestHash: row.RequestHash, TypeName: row.TypeName, Identifier: row.Identifier, Operation: row.Operation, Status: row.Status, Phase: row.Phase, RoleARN: row.RoleArn, Desired: row.Desired, Before: row.BeforeModel, Patch: row.Patch, Model: row.Model, ErrorCode: row.ErrorCode, Message: row.Message, Created: row.Created.UTC(), EventTime: row.EventTime.UTC(), Due: row.Due.UTC(), Revision: uint64(row.Revision)}
	err := json.Unmarshal([]byte(row.CallerJson), &out.Caller)
	return out, err
}
func (r reader) Request(token string) (domain.RequestRecord, error) {
	row, err := r.q.Request(r.ctx, token)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.RequestRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.RequestRecord{}, err
	}
	return decode(row)
}
func (r reader) Requests(scope domain.Scope) ([]domain.RequestRecord, error) {
	rows, err := r.q.Requests(r.ctx, sqlcgen.RequestsParams{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RequestRecord, len(rows))
	for i, row := range rows {
		out[i], err = decode(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (r reader) NextRequest() (domain.RequestRecord, bool, error) {
	row, err := r.q.NextRequest(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.RequestRecord{}, false, nil
	}
	if err != nil {
		return domain.RequestRecord{}, false, err
	}
	out, err := decode(row)
	return out, err == nil, err
}
func (w writer) PutRequest(v domain.RequestRecord) error {
	if v.Revision > math.MaxInt64 {
		return fmt.Errorf("cloudcontrol request revision exceeds SQLite range")
	}
	caller, err := json.Marshal(v.Caller)
	if err != nil {
		return err
	}
	return w.q.PutRequest(w.ctx, sqlcgen.PutRequestParams{Token: v.Token, Partition: v.Scope.Partition, AccountID: v.Scope.Account, Region: v.Scope.Region, ClientToken: v.ClientToken, RequestHash: v.RequestHash, TypeName: v.TypeName, Identifier: v.Identifier, Operation: v.Operation, Status: v.Status, Phase: v.Phase, RoleArn: v.RoleARN, Desired: v.Desired, BeforeModel: v.Before, Patch: v.Patch, Model: v.Model, ErrorCode: v.ErrorCode, Message: v.Message, CallerJson: string(caller), Created: v.Created.UTC(), EventTime: v.EventTime.UTC(), Due: v.Due.UTC(), Revision: int64(v.Revision)})
}

var _ domain.Repository = (*Repository)(nil)
