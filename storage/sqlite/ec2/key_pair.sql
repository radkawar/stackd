-- name: GetKeyPair :one
SELECT * FROM ec2_key_pairs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListKeyPairs :many
SELECT * FROM ec2_key_pairs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PutKeyPair :exec
INSERT INTO ec2_key_pairs (partition, account_id, region, resource_id, key_pair_id, key_name, key_fingerprint, key_type, public_key, create_time, tags_present)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(key_pair_id), sqlc.arg(key_name), sqlc.arg(key_fingerprint), sqlc.arg(key_type), sqlc.arg(public_key), sqlc.arg(create_time), sqlc.arg(tags_present))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET key_pair_id = excluded.key_pair_id, key_name = excluded.key_name, key_fingerprint = excluded.key_fingerprint, key_type = excluded.key_type, public_key = excluded.public_key, create_time = excluded.create_time, tags_present = excluded.tags_present;

-- name: DeleteKeyPair :execrows
DELETE FROM ec2_key_pairs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListKeyPairTags :many
SELECT * FROM ec2_key_pair_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutKeyPairTag :exec
INSERT INTO ec2_key_pair_tags (partition, account_id, region, resource_id, position, key, value)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(key), sqlc.arg(value));

-- name: DeleteKeyPairTags :exec
DELETE FROM ec2_key_pair_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);
