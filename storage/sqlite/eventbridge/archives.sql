-- name: GetArchive :one
SELECT * FROM eventbridge_archives WHERE partition=? AND account=? AND region=? AND name=?;
-- name: GetArchiveByID :one
SELECT * FROM eventbridge_archives WHERE id=?;
-- name: ListArchives :many
SELECT * FROM eventbridge_archives WHERE partition=? AND account=? AND region=? ORDER BY name;
-- name: PutArchive :exec
INSERT INTO eventbridge_archives(partition,account,region,name,id,source_partition,source_account,source_region,source_bus_name,description,kms_key_identifier,key_arn,pattern_content,pattern_data_key,retention_days,created,state,state_reason,version,event_count,size_bytes,key_version,migration_due_seconds,migration_due_nanos,previous_key_arn,previous_kms_key_identifier,cfn_owner)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,name) DO UPDATE SET id=excluded.id,source_partition=excluded.source_partition,source_account=excluded.source_account,source_region=excluded.source_region,source_bus_name=excluded.source_bus_name,description=excluded.description,kms_key_identifier=excluded.kms_key_identifier,key_arn=excluded.key_arn,pattern_content=excluded.pattern_content,pattern_data_key=excluded.pattern_data_key,retention_days=excluded.retention_days,created=excluded.created,state=excluded.state,state_reason=excluded.state_reason,version=excluded.version,event_count=excluded.event_count,size_bytes=excluded.size_bytes,key_version=excluded.key_version,migration_due_seconds=excluded.migration_due_seconds,migration_due_nanos=excluded.migration_due_nanos,previous_key_arn=excluded.previous_key_arn,previous_kms_key_identifier=excluded.previous_kms_key_identifier,cfn_owner=excluded.cfn_owner;
-- name: DeleteArchive :exec
DELETE FROM eventbridge_archives WHERE partition=? AND account=? AND region=? AND name=?;
-- name: GetArchiveEntry :one
SELECT * FROM eventbridge_archive_entries WHERE archive_id=? AND id=?;
-- name: NextArchiveEntry :one
SELECT * FROM eventbridge_archive_entries
WHERE archive_id=@archive_id
AND (event_seconds,event_nanos)>=(CAST(@start_seconds AS INTEGER),CAST(@start_nanos AS INTEGER))
AND (event_seconds,event_nanos)<(CAST(@end_seconds AS INTEGER),CAST(@end_nanos AS INTEGER))
AND (CAST(@after_id AS TEXT)='' OR (event_seconds,event_nanos,id)>(CAST(@after_seconds AS INTEGER),CAST(@after_nanos AS INTEGER),CAST(@after_id AS TEXT)))
ORDER BY event_seconds,event_nanos,id LIMIT 1;
-- name: NextArchiveExpiration :one
SELECT * FROM eventbridge_archive_entries WHERE expires_seconds IS NOT NULL ORDER BY expires_seconds,expires_nanos,archive_id,id LIMIT 1;
-- name: PutArchiveEntry :exec
INSERT INTO eventbridge_archive_entries(archive_id,id,event_seconds,event_nanos,ingested_seconds,ingested_nanos,expires_seconds,expires_nanos,content,data_key,size_bytes,key_version,rule_context)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(archive_id,id) DO UPDATE SET event_seconds=excluded.event_seconds,event_nanos=excluded.event_nanos,ingested_seconds=excluded.ingested_seconds,ingested_nanos=excluded.ingested_nanos,expires_seconds=excluded.expires_seconds,expires_nanos=excluded.expires_nanos,content=excluded.content,data_key=excluded.data_key,size_bytes=excluded.size_bytes,key_version=excluded.key_version,rule_context=excluded.rule_context;
-- name: DeleteArchiveEntry :exec
DELETE FROM eventbridge_archive_entries WHERE archive_id=? AND id=?;
-- name: UpdateArchiveEntryRetention :exec
UPDATE eventbridge_archive_entries
SET expires_seconds=CASE WHEN CAST(@days AS INTEGER)=0 THEN NULL ELSE ingested_seconds+CAST(@days AS INTEGER)*86400 END,
expires_nanos=CASE WHEN CAST(@days AS INTEGER)=0 THEN 0 ELSE ingested_nanos END
WHERE archive_id=@archive_id;
-- name: NextArchiveMigration :one
SELECT * FROM eventbridge_archives WHERE migration_due_seconds IS NOT NULL ORDER BY migration_due_seconds,migration_due_nanos,id LIMIT 1;
-- name: NextArchiveMigrationEntry :one
SELECT * FROM eventbridge_archive_entries WHERE archive_id=? AND key_version<? ORDER BY key_version,id LIMIT 1;
