-- name: GetDocumentDBMapping :one
SELECT * FROM lambda_documentdb_mappings WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutDocumentDBMapping :exec
INSERT INTO lambda_documentdb_mappings(partition,account,region,uuid,database_name,collection_name,full_document,secret_arn,starting_position,starting_position_timestamp,batching_window_ns,incarnation)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,uuid) DO UPDATE SET database_name=excluded.database_name,collection_name=excluded.collection_name,full_document=excluded.full_document,secret_arn=excluded.secret_arn,starting_position=excluded.starting_position,starting_position_timestamp=excluded.starting_position_timestamp,batching_window_ns=excluded.batching_window_ns,incarnation=excluded.incarnation;

-- name: GetDocumentDBCheckpoint :one
SELECT * FROM lambda_documentdb_checkpoints WHERE partition=? AND account=? AND region=? AND uuid=?;

-- name: PutDocumentDBCheckpoint :exec
INSERT INTO lambda_documentdb_checkpoints(partition,account,region,uuid,incarnation,resume_token,start_seconds,start_increment)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,uuid) DO UPDATE SET incarnation=excluded.incarnation,resume_token=excluded.resume_token,start_seconds=excluded.start_seconds,start_increment=excluded.start_increment;

-- name: DeleteDocumentDBCheckpoint :exec
DELETE FROM lambda_documentdb_checkpoints WHERE partition=? AND account=? AND region=? AND uuid=?;
