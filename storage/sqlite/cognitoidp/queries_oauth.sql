-- name: GetOAuth :one
SELECT * FROM cognitoidp_oauth WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND token = ?;

-- name: PutOAuth :exec
INSERT INTO cognitoidp_oauth (
 partition, account_id, region, pool_id, token, client_id, provider_name, redirect_uri, client_state, nonce,
 pkce_challenge, upstream_nonce, upstream_verifier, scope, username, phase, expires
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
);

-- name: DeleteOAuth :exec
DELETE FROM cognitoidp_oauth WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND token = ?;

-- name: DeleteExpiredOAuth :exec
DELETE FROM cognitoidp_oauth WHERE partition = ? AND account_id = ? AND region = ? AND pool_id = ? AND expires <= ?;
