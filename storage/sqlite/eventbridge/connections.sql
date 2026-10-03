-- name: GetConnection :one
SELECT * FROM eventbridge_connections WHERE partition=? AND account=? AND region=? AND name=?;

-- name: GetConnectionByID :one
SELECT * FROM eventbridge_connections WHERE id=?;

-- name: ListConnections :many
SELECT * FROM eventbridge_connections WHERE partition=? AND account=? AND region=? ORDER BY name;

-- name: ConnectionARNs :many
SELECT CAST('arn:' || partition || ':events:' || region || ':' || account || ':connection/' || name || '/' || id AS TEXT) AS arn FROM eventbridge_connections WHERE partition=? AND account=? ORDER BY arn;

-- name: NextConnectionJob :one
SELECT * FROM eventbridge_connections WHERE due_seconds IS NOT NULL ORDER BY due_seconds,due_nanos,id LIMIT 1;

-- name: GetConnectionParameters :many
SELECT * FROM eventbridge_connection_parameters WHERE connection_id=? ORDER BY ordinal;

-- name: DeleteConnection :exec
DELETE FROM eventbridge_connections WHERE partition=? AND account=? AND region=? AND name=?;

-- name: DeleteConnectionParameters :exec
DELETE FROM eventbridge_connection_parameters WHERE connection_id=?;

-- name: PutConnectionParameter :exec
INSERT INTO eventbridge_connection_parameters(connection_id,ordinal,target,location,key,value,secret) VALUES(?,?,?,?,?,?,?);

-- name: PutConnection :exec
INSERT INTO eventbridge_connections(partition,account,region,name,id,description,authorization_type,state,state_reason,secret_arn,kms_key_identifier,username,api_key_name,client_id,authorization_endpoint,oauth_method,has_auth,has_invocation,has_oauth_http,created,modified,last_authorized,due_seconds,due_nanos,version)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,name) DO UPDATE SET id=excluded.id,description=excluded.description,authorization_type=excluded.authorization_type,state=excluded.state,state_reason=excluded.state_reason,secret_arn=excluded.secret_arn,kms_key_identifier=excluded.kms_key_identifier,username=excluded.username,api_key_name=excluded.api_key_name,client_id=excluded.client_id,authorization_endpoint=excluded.authorization_endpoint,oauth_method=excluded.oauth_method,has_auth=excluded.has_auth,has_invocation=excluded.has_invocation,has_oauth_http=excluded.has_oauth_http,created=excluded.created,modified=excluded.modified,last_authorized=excluded.last_authorized,due_seconds=excluded.due_seconds,due_nanos=excluded.due_nanos,version=excluded.version;
