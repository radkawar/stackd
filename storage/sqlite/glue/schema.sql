-- name: GetGlueSchema :one
SELECT * FROM glue_schemas WHERE partition=? AND account_id=? AND region=? AND registry_name=? AND schema_name=?;
-- name: ListGlueSchemas :many
SELECT * FROM glue_schemas WHERE partition=? AND account_id=? AND region=? AND (sqlc.arg(registry_filter)='' OR registry_name=sqlc.arg(registry_filter)) ORDER BY registry_name,schema_name;
-- name: PutGlueSchema :exec
INSERT INTO glue_schemas (partition,account_id,region,registry_name,schema_name,description,data_format,compatibility,status,checkpoint,latest_version,next_version,created_at,updated_at,due_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (partition,account_id,region,registry_name,schema_name) DO UPDATE SET
 description=excluded.description,data_format=excluded.data_format,compatibility=excluded.compatibility,status=excluded.status,checkpoint=excluded.checkpoint,latest_version=excluded.latest_version,next_version=excluded.next_version,created_at=excluded.created_at,updated_at=excluded.updated_at,due_at=excluded.due_at;
-- name: DeleteGlueSchema :exec
DELETE FROM glue_schemas WHERE partition=? AND account_id=? AND region=? AND registry_name=? AND schema_name=?;
-- name: ListGlueSchemaTags :many
SELECT tag_key,tag_value FROM glue_schema_tags WHERE partition=? AND account_id=? AND region=? AND registry_name=? AND schema_name=? ORDER BY tag_key;
-- name: DeleteGlueSchemaTags :exec
DELETE FROM glue_schema_tags WHERE partition=? AND account_id=? AND region=? AND registry_name=? AND schema_name=?;
-- name: PutGlueSchemaTag :exec
INSERT INTO glue_schema_tags (partition,account_id,region,registry_name,schema_name,tag_key,tag_value) VALUES (?,?,?,?,?,?,?);
-- name: GetGlueSchemaVersion :one
SELECT * FROM glue_schema_versions WHERE partition=? AND account_id=? AND region=? AND registry_name=? AND schema_name=? AND version_number=?;
-- name: GetGlueSchemaVersionByID :one
SELECT * FROM glue_schema_versions WHERE partition=? AND account_id=? AND region=? AND version_id=?;
-- name: ListGlueSchemaVersions :many
SELECT * FROM glue_schema_versions WHERE partition=? AND account_id=? AND region=? AND registry_name=? AND schema_name=? ORDER BY version_number DESC;
-- name: PutGlueSchemaVersion :exec
INSERT INTO glue_schema_versions (partition,account_id,region,registry_name,schema_name,version_number,version_id,definition,canonical,status,created_at,due_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (partition,account_id,region,registry_name,schema_name,version_number) DO UPDATE SET
 version_id=excluded.version_id,definition=excluded.definition,canonical=excluded.canonical,status=excluded.status,created_at=excluded.created_at,due_at=excluded.due_at;
-- name: DeleteGlueSchemaVersion :exec
DELETE FROM glue_schema_versions WHERE partition=? AND account_id=? AND region=? AND registry_name=? AND schema_name=? AND version_number=?;
-- name: ListGlueSchemaMetadata :many
SELECT * FROM glue_schema_metadata WHERE version_id=? ORDER BY metadata_key,ordinal,metadata_value;
-- name: PutGlueSchemaMetadata :exec
INSERT INTO glue_schema_metadata (version_id,metadata_key,metadata_value,created_at,ordinal) VALUES (?,?,?,?,?)
ON CONFLICT (version_id,metadata_key,metadata_value) DO UPDATE SET created_at=excluded.created_at,ordinal=excluded.ordinal;
-- name: DeleteGlueSchemaMetadata :exec
DELETE FROM glue_schema_metadata WHERE version_id=? AND metadata_key=? AND metadata_value=?;
-- name: NextGlueSchemaDeletion :one
SELECT * FROM glue_schemas WHERE status='DELETING' ORDER BY due_at,partition,account_id,region,registry_name,schema_name LIMIT 1;
-- name: NextGlueSchemaVersionDeletion :one
SELECT * FROM glue_schema_versions WHERE status='DELETING' ORDER BY due_at,version_id LIMIT 1;
