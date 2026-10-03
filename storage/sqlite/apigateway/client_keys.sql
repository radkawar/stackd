-- name: GetClientKey :one
SELECT * FROM apigateway_client_keys WHERE partition = ? AND account_id = ? AND region = ? AND client_key_id = ?;

-- name: GetClientKeyByValue :one
SELECT * FROM apigateway_client_keys WHERE partition = ? AND account_id = ? AND region = ? AND value = ?;

-- name: ListClientKeys :many
SELECT * FROM apigateway_client_keys WHERE partition = ? AND account_id = ? AND region = ? ORDER BY client_key_id;

-- name: PutClientKey :exec
INSERT INTO apigateway_client_keys (partition, account_id, region, client_key_id, name, description, customer_id, value, enabled, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, client_key_id) DO UPDATE SET name = excluded.name, description = excluded.description, customer_id = excluded.customer_id, value = excluded.value, enabled = excluded.enabled, created = excluded.created, updated = excluded.updated;

-- name: DeleteClientKey :exec
DELETE FROM apigateway_client_keys WHERE partition = ? AND account_id = ? AND region = ? AND client_key_id = ?;

-- name: ListClientKeyTags :many
SELECT key, value FROM apigateway_client_key_tags WHERE partition = ? AND account_id = ? AND region = ? AND client_key_id = ? ORDER BY key;

-- name: PutClientKeyTag :exec
INSERT INTO apigateway_client_key_tags (partition, account_id, region, client_key_id, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: DeleteClientKeyTags :exec
DELETE FROM apigateway_client_key_tags WHERE partition = ? AND account_id = ? AND region = ? AND client_key_id = ?;

-- name: ListClientKeyStages :many
SELECT api_id, stage_name FROM apigateway_client_key_stages WHERE partition = ? AND account_id = ? AND region = ? AND client_key_id = ? ORDER BY ordinal;

-- name: PutClientKeyStage :exec
INSERT INTO apigateway_client_key_stages (partition, account_id, region, client_key_id, ordinal, api_id, stage_name) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: DeleteClientKeyStages :exec
DELETE FROM apigateway_client_key_stages WHERE partition = ? AND account_id = ? AND region = ? AND client_key_id = ?;
