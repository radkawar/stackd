-- name: GetAPIDestination :one
SELECT * FROM eventbridge_api_destinations WHERE partition=? AND account=? AND region=? AND name=?;

-- name: ListAPIDestinations :many
SELECT * FROM eventbridge_api_destinations WHERE partition=? AND account=? AND region=? ORDER BY name;

-- name: PutAPIDestination :exec
INSERT INTO eventbridge_api_destinations(partition,account,region,name,id,description,connection_arn,endpoint,method,rate,created,modified,rate_window,rate_count,version,cfn_owner)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,name) DO UPDATE SET id=excluded.id,description=excluded.description,connection_arn=excluded.connection_arn,endpoint=excluded.endpoint,method=excluded.method,rate=excluded.rate,created=excluded.created,modified=excluded.modified,rate_window=excluded.rate_window,rate_count=excluded.rate_count,version=excluded.version,cfn_owner=excluded.cfn_owner;

-- name: DeleteAPIDestination :exec
DELETE FROM eventbridge_api_destinations WHERE partition=? AND account=? AND region=? AND name=?;
