package s3tables

import (
	"context"
	"database/sql"
	"errors"

	domain "stackd/storage/s3tables"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/s3tables/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, f func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, t *sql.Tx) error { return f(reader{ctx, sqlcgen.New(t)}) })
}
func (r *Repository) Update(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}
func (r *Repository) Attempt(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}
func bucket(v sqlcgen.S3tablesBucket) domain.Bucket {
	return domain.Bucket{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ARN: v.Arn, Name: v.Name, ID: v.ID, Created: v.Created}
}
func namespace(v sqlcgen.S3tablesNamespace) domain.Namespace {
	return domain.Namespace{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, BucketARN: v.BucketArn, Name: v.Name, ID: v.ID, Created: v.Created}
}
func table(v sqlcgen.S3tablesTable) domain.Table {
	return domain.Table{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ARN: v.Arn, BucketARN: v.BucketArn, Namespace: v.Namespace, Name: v.Name, ID: v.ID, VersionToken: v.VersionToken, Warehouse: v.Warehouse, MetadataLocation: v.MetadataLocation, Created: v.Created, Modified: v.Modified, Deleted: v.Deleted, Purged: v.Purged, CleanupAt: v.CleanupAt}
}
func (r reader) Bucket(sc domain.Scope, arn string) (domain.Bucket, error) {
	v, e := r.q.GetBucket(r.ctx, sqlcgen.GetBucketParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: arn})
	return bucket(v), missing(e)
}
func (r reader) Buckets(sc domain.Scope) ([]domain.Bucket, error) {
	rows, e := r.q.ListBuckets(r.ctx, sqlcgen.ListBucketsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Bucket, 0, len(rows))
	for _, v := range rows {
		out = append(out, bucket(v))
	}
	return out, nil
}
func (r reader) Namespace(sc domain.Scope, b, n string) (domain.Namespace, error) {
	v, e := r.q.GetNamespace(r.ctx, sqlcgen.GetNamespaceParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, BucketArn: b, Name: n})
	return namespace(v), missing(e)
}
func (r reader) Namespaces(sc domain.Scope, b string) ([]domain.Namespace, error) {
	rows, e := r.q.ListNamespaces(r.ctx, sqlcgen.ListNamespacesParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, BucketArn: b})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Namespace, 0, len(rows))
	for _, v := range rows {
		out = append(out, namespace(v))
	}
	return out, nil
}
func (r reader) Table(sc domain.Scope, b, n, name string) (domain.Table, error) {
	v, e := r.q.GetTable(r.ctx, sqlcgen.GetTableParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, BucketArn: b, Namespace: n, Name: name})
	return table(v), missing(e)
}
func (r reader) TableColumns(sc domain.Scope, arn string) ([]domain.Column, error) {
	rows, e := r.q.ListTableColumns(r.ctx, sqlcgen.ListTableColumnsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, TableArn: arn})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Column, 0, len(rows))
	for _, v := range rows {
		out = append(out, domain.Column{Name: v.Name, Type: v.Type, Comment: v.Comment})
	}
	return out, nil
}
func (r reader) Tables(sc domain.Scope, b string) ([]domain.Table, error) {
	rows, e := r.q.ListTables(r.ctx, sqlcgen.ListTablesParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, BucketArn: b})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Table, 0, len(rows))
	for _, v := range rows {
		out = append(out, table(v))
	}
	return out, nil
}
func (r reader) Warehouse(sc domain.Scope, warehouse string) (domain.Table, error) {
	v, e := r.q.GetWarehouse(r.ctx, sqlcgen.GetWarehouseParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Warehouse: warehouse})
	return table(v), missing(e)
}
func (r reader) PendingTables() ([]domain.Table, error) {
	rows, e := r.q.ListPendingTables(r.ctx)
	if e != nil {
		return nil, e
	}
	out := make([]domain.Table, 0, len(rows))
	for _, v := range rows {
		out = append(out, table(v))
	}
	return out, nil
}
func (w writer) PutBucket(v domain.Bucket) error {
	return w.q.PutBucket(w.ctx, sqlcgen.PutBucketParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.ARN, Name: v.Name, ID: v.ID, Created: v.Created})
}
func (w writer) DeleteBucket(sc domain.Scope, arn string) error {
	return w.q.DeleteBucket(w.ctx, sqlcgen.DeleteBucketParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, Arn: arn})
}
func (w writer) PutNamespace(v domain.Namespace) error {
	return w.q.PutNamespace(w.ctx, sqlcgen.PutNamespaceParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, BucketArn: v.BucketARN, Name: v.Name, ID: v.ID, Created: v.Created})
}
func (w writer) DeleteNamespace(sc domain.Scope, b, n string) error {
	return w.q.DeleteNamespace(w.ctx, sqlcgen.DeleteNamespaceParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, BucketArn: b, Name: n})
}
func (w writer) PutTable(v domain.Table) error {
	return w.q.PutTable(w.ctx, sqlcgen.PutTableParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Arn: v.ARN, BucketArn: v.BucketARN, Namespace: v.Namespace, Name: v.Name, ID: v.ID, VersionToken: v.VersionToken, Warehouse: v.Warehouse, MetadataLocation: v.MetadataLocation, Created: v.Created, Modified: v.Modified, Deleted: v.Deleted, Purged: v.Purged, CleanupAt: v.CleanupAt})
}
func (w writer) PutTableColumns(sc domain.Scope, arn string, columns []domain.Column) error {
	if e := w.q.DeleteTableColumns(w.ctx, sqlcgen.DeleteTableColumnsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, TableArn: arn}); e != nil {
		return e
	}
	for i, column := range columns {
		if e := w.q.PutTableColumn(w.ctx, sqlcgen.PutTableColumnParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, TableArn: arn, Ordinal: int64(i), Name: column.Name, Type: column.Type, Comment: column.Comment}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) DeleteTable(sc domain.Scope, b, n, name string) error {
	return w.q.DeleteTable(w.ctx, sqlcgen.DeleteTableParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, BucketArn: b, Namespace: n, Name: name})
}

var _ domain.Repository = (*Repository)(nil)
