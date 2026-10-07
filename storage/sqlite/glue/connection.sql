-- name: GetGlueConnection :one
SELECT * FROM glue_connections WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: ListGlueConnections :many
SELECT * FROM glue_connections WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: DeleteGlueConnection :exec
DELETE FROM glue_connections WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: PutGlueConnection :exec
INSERT INTO glue_connections (cfn_owner,partition,account_id,region,name,connection_type,description,properties,match_criteria,physical_requirements,athena_properties,spark_properties,python_properties,tags,password,password_cipher,created_at,updated_at,last_updated_by)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,name) DO UPDATE SET connection_type=excluded.connection_type,description=excluded.description,properties=excluded.properties,match_criteria=excluded.match_criteria,physical_requirements=excluded.physical_requirements,athena_properties=excluded.athena_properties,spark_properties=excluded.spark_properties,python_properties=excluded.python_properties,tags=excluded.tags,password=excluded.password,password_cipher=excluded.password_cipher,updated_at=excluded.updated_at,last_updated_by=excluded.last_updated_by;
-- name: GetGlueConnectionEncryption :one
SELECT * FROM glue_connection_encryption WHERE partition = ? AND account_id = ? AND region = ?;
-- name: PutGlueConnectionEncryption :exec
INSERT INTO glue_connection_encryption (cfn_owner,partition,account_id,region,key_id,return_encrypted) VALUES (?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region) DO UPDATE SET key_id=excluded.key_id,return_encrypted=excluded.return_encrypted;
-- name: DeleteGlueConnectionEncryption :exec
DELETE FROM glue_connection_encryption WHERE partition=? AND account_id=? AND region=?;
