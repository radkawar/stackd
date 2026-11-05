-- name: GetBucket :one
SELECT * FROM s3tables_buckets WHERE partition=? AND account_id=? AND region=? AND arn=?;
-- name: ListBuckets :many
SELECT * FROM s3tables_buckets WHERE partition=? AND account_id=? AND region=? ORDER BY name;
-- name: PutBucket :exec
INSERT INTO s3tables_buckets(partition,account_id,region,arn,name,id,created) VALUES(?,?,?,?,?,?,?);
-- name: DeleteBucket :exec
DELETE FROM s3tables_buckets WHERE partition=? AND account_id=? AND region=? AND arn=?;
-- name: GetNamespace :one
SELECT * FROM s3tables_namespaces WHERE partition=? AND account_id=? AND region=? AND bucket_arn=? AND name=?;
-- name: ListNamespaces :many
SELECT * FROM s3tables_namespaces WHERE partition=? AND account_id=? AND region=? AND bucket_arn=? ORDER BY name;
-- name: PutNamespace :exec
INSERT INTO s3tables_namespaces(partition,account_id,region,bucket_arn,name,id,created) VALUES(?,?,?,?,?,?,?);
-- name: DeleteNamespace :exec
DELETE FROM s3tables_namespaces WHERE partition=? AND account_id=? AND region=? AND bucket_arn=? AND name=?;
-- name: GetTable :one
SELECT * FROM s3tables_tables WHERE partition=? AND account_id=? AND region=? AND bucket_arn=? AND namespace=? AND name=? AND deleted=0;
-- name: ListTables :many
SELECT * FROM s3tables_tables WHERE partition=? AND account_id=? AND region=? AND bucket_arn=? AND deleted=0 ORDER BY namespace,name;
-- name: GetWarehouse :one
SELECT * FROM s3tables_tables WHERE partition=? AND account_id=? AND region=? AND warehouse=?;
-- name: ListPendingTables :many
SELECT * FROM s3tables_tables WHERE deleted=1 AND purged=0 ORDER BY cleanup_at,arn;
-- name: PutTable :exec
INSERT INTO s3tables_tables(partition,account_id,region,arn,bucket_arn,namespace,name,id,version_token,warehouse,metadata_location,created,modified,deleted,purged,cleanup_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(arn) DO UPDATE SET namespace=excluded.namespace,name=excluded.name,version_token=excluded.version_token,metadata_location=excluded.metadata_location,modified=excluded.modified,deleted=excluded.deleted,purged=excluded.purged,cleanup_at=excluded.cleanup_at;
-- name: DeleteTable :exec
UPDATE s3tables_tables SET deleted=1 WHERE partition=? AND account_id=? AND region=? AND bucket_arn=? AND namespace=? AND name=? AND deleted=0;
-- name: ListTableColumns :many
SELECT c.name,c.type,c.comment FROM s3tables_columns c
JOIN s3tables_tables t ON t.arn=c.table_arn AND t.partition=c.partition AND t.account_id=c.account_id AND t.region=c.region
WHERE c.partition=? AND c.account_id=? AND c.region=? AND c.table_arn=? AND t.deleted=0 ORDER BY c.ordinal;
-- name: DeleteTableColumns :exec
DELETE FROM s3tables_columns WHERE partition=? AND account_id=? AND region=? AND table_arn=?;
-- name: PutTableColumn :exec
INSERT INTO s3tables_columns(partition,account_id,region,table_arn,ordinal,name,type,comment) VALUES(?,?,?,?,?,?,?,?);
