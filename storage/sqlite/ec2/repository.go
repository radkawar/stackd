// Package ec2 persists scoped EC2 networking controls and ordered child sets.
package ec2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx, sqlcgen.New(tx)})
	})
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx, sqlcgen.New(tx)}})
	})
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx, sqlcgen.New(tx)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }

var _ domain.Repository = (*Repository)(nil)
var _ domain.Reader = reader{}
var _ domain.Transaction = writer{}

func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func deleted(n int64, err error) error {
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
func nullableString[T ~string](v *T) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*v), Valid: true}
}
func stringPointer[T ~string](v sql.NullString) *T {
	if !v.Valid {
		return nil
	}
	x := T(v.String)
	return &x
}
func nullableInteger[T ~int32](v *T) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*v), Valid: true}
}
func integerPointer[T ~int32](v sql.NullInt64) *T {
	if !v.Valid {
		return nil
	}
	x := T(v.Int64)
	return &x
}
func nullableBool[T ~bool](v *T) sql.NullBool {
	if v == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: bool(*v), Valid: true}
}
func boolPointer[T ~bool](v sql.NullBool) *T {
	if !v.Valid {
		return nil
	}
	x := T(v.Bool)
	return &x
}

// JSON columns contain only individually typed nested configuration objects.
// Ordered protocol sets and resource tags live in their own relational tables.
type jsonWriteField struct {
	target *[]byte
	value  any
}

func marshalFields(fields ...jsonWriteField) error {
	for _, field := range fields {
		data, err := json.Marshal(field.value)
		if err != nil {
			return err
		}
		*field.target = data
	}
	return nil
}

type jsonReadField struct {
	source []byte
	target any
}

func unmarshalFields(fields ...jsonReadField) error {
	for _, field := range fields {
		if err := json.Unmarshal(field.source, field.target); err != nil {
			return err
		}
	}
	return nil
}

// The generated object's omitempty tag would collapse an empty tag set to nil.
// Shadow only that nested set so JSON preserves the same nil/empty contract as
// the normalized child sets. The API decoder reads the explicit Tags member.
func encryptionControlJSON(v *api.VpcEncryptionControl) any {
	if v == nil {
		return nil
	}
	return struct {
		*api.VpcEncryptionControl
		Tags api.TagList `json:"Tags"`
	}{v, v.Tags}
}

func (w writer) NextID(scope domain.Scope, prefix string) (string, error) {
	n, err := w.q.GetSequence(w.ctx, sqlcgen.GetSequenceParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Prefix: prefix})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	next := uint64(n) + 1
	id, err := domain.FormatResourceID(scope, prefix, next)
	if err != nil {
		return "", err
	}
	if err := w.q.PutSequence(w.ctx, sqlcgen.PutSequenceParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Prefix: prefix, Sequence: sqlite.Uint64(next)}); err != nil {
		return "", err
	}
	return id, nil
}
