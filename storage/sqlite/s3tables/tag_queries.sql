-- name: GetTableByARN :one
SELECT * FROM s3tables_tables WHERE partition=? AND account_id=? AND region=? AND arn=? AND deleted=0;
-- name: ListResourceTags :many
SELECT key,value FROM s3tables_tags WHERE partition=? AND account_id=? AND region=? AND resource_arn=? ORDER BY key;
-- name: DeleteResourceTags :exec
DELETE FROM s3tables_tags WHERE partition=? AND account_id=? AND region=? AND resource_arn=?;
-- name: PutResourceTag :exec
INSERT INTO s3tables_tags(partition,account_id,region,resource_arn,key,value) VALUES(?,?,?,?,?,?);
