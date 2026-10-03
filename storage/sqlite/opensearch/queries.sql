-- name: GetDomain :one
SELECT * FROM opensearch_domain WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: ListDomains :many
SELECT * FROM opensearch_domain WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY name;

-- name: AllDomains :many
SELECT * FROM opensearch_domain ORDER BY partition, account_id, region, name;

-- name: PutDomain :exec
INSERT INTO opensearch_domain (
 partition, account_id, region, name, incarnation, engine_version, status,
 native_endpoint, last_error, access_policy, instance_type, instance_count,
 created, updated, due, version, config_version
) VALUES (
 sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name),
 sqlc.arg(incarnation), sqlc.arg(engine_version), sqlc.arg(status),
 sqlc.arg(native_endpoint), sqlc.arg(last_error), sqlc.arg(access_policy),
 sqlc.arg(instance_type), sqlc.arg(instance_count), sqlc.arg(created),
 sqlc.arg(updated), sqlc.arg(due), sqlc.arg(version), sqlc.arg(config_version)
) ON CONFLICT (partition, account_id, region, name) DO UPDATE SET
 incarnation = excluded.incarnation, engine_version = excluded.engine_version,
 status = excluded.status, native_endpoint = excluded.native_endpoint,
 last_error = excluded.last_error, access_policy = excluded.access_policy,
 instance_type = excluded.instance_type, instance_count = excluded.instance_count,
 created = excluded.created, updated = excluded.updated, due = excluded.due,
 version = excluded.version, config_version = excluded.config_version;

-- name: DeleteDomain :exec
DELETE FROM opensearch_domain WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: ListAdvancedOptions :many
SELECT option_key, option_value FROM opensearch_advanced_option WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY option_key;

-- name: PutAdvancedOption :exec
INSERT INTO opensearch_advanced_option (partition, account_id, region, name, option_key, option_value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(option_key), sqlc.arg(option_value));

-- name: DeleteAdvancedOptions :exec
DELETE FROM opensearch_advanced_option WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: ListPolicyPrincipals :many
SELECT principal_arn, principal_id FROM opensearch_policy_principal WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY principal_arn;

-- name: PutPolicyPrincipal :exec
INSERT INTO opensearch_policy_principal (partition, account_id, region, name, principal_arn, principal_id) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(principal_arn), sqlc.arg(principal_id));

-- name: DeletePolicyPrincipals :exec
DELETE FROM opensearch_policy_principal WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: ListTags :many
SELECT tag_key, tag_value FROM opensearch_tag WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY tag_key;

-- name: PutTag :exec
INSERT INTO opensearch_tag (partition, account_id, region, name, tag_key, tag_value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(tag_key), sqlc.arg(tag_value));

-- name: DeleteTags :exec
DELETE FROM opensearch_tag WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);
