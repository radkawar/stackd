-- name: GetInstanceCreditDefault :one
SELECT * FROM ec2_instance_credit_defaults WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND family = sqlc.arg(family);

-- name: PutInstanceCreditDefault :exec
INSERT INTO ec2_instance_credit_defaults (partition, account_id, region, family, mode, changes_present) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(family), sqlc.arg(mode), sqlc.arg(changes_present))
ON CONFLICT (partition, account_id, region, family) DO UPDATE SET mode = excluded.mode, changes_present = excluded.changes_present;

-- name: ListInstanceCreditDefaultChanges :many
SELECT changed_at FROM ec2_instance_credit_default_changes WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND family = sqlc.arg(family) ORDER BY position;

-- name: DeleteInstanceCreditDefaultChanges :exec
DELETE FROM ec2_instance_credit_default_changes WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND family = sqlc.arg(family);

-- name: PutInstanceCreditDefaultChange :exec
INSERT INTO ec2_instance_credit_default_changes (partition, account_id, region, family, position, changed_at) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(family), sqlc.arg(position), sqlc.arg(changed_at));

-- name: GetInstanceCreditLaunches :one
SELECT * FROM ec2_instance_credit_launches WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region);

-- name: PutInstanceCreditLaunches :exec
INSERT INTO ec2_instance_credit_launches (partition, account_id, region, starts_present) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(starts_present))
ON CONFLICT (partition, account_id, region) DO UPDATE SET starts_present = excluded.starts_present;

-- name: ListInstanceCreditLaunchStarts :many
SELECT started_at FROM ec2_instance_credit_launch_starts WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY position;

-- name: DeleteInstanceCreditLaunchStarts :exec
DELETE FROM ec2_instance_credit_launch_starts WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region);

-- name: PutInstanceCreditLaunchStart :exec
INSERT INTO ec2_instance_credit_launch_starts (partition, account_id, region, position, started_at) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(position), sqlc.arg(started_at));

-- name: GetInstanceCreditModification :one
SELECT * FROM ec2_instance_credit_modifications WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: PutInstanceCreditModification :exec
INSERT INTO ec2_instance_credit_modifications (partition, account_id, region, token, specifications_present, successful_present, unsuccessful_present) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(specifications_present), sqlc.arg(successful_present), sqlc.arg(unsuccessful_present))
ON CONFLICT (partition, account_id, region, token) DO UPDATE SET specifications_present = excluded.specifications_present, successful_present = excluded.successful_present, unsuccessful_present = excluded.unsuccessful_present;

-- name: ListInstanceCreditModificationSpecs :many
SELECT * FROM ec2_instance_credit_modification_specs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token) ORDER BY position;

-- name: DeleteInstanceCreditModificationSpecs :exec
DELETE FROM ec2_instance_credit_modification_specs WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: PutInstanceCreditModificationSpec :exec
INSERT INTO ec2_instance_credit_modification_specs (partition, account_id, region, token, position, instance_id, mode) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(position), sqlc.arg(instance_id), sqlc.arg(mode));

-- name: ListInstanceCreditModificationSuccesses :many
SELECT * FROM ec2_instance_credit_modification_successes WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token) ORDER BY position;

-- name: DeleteInstanceCreditModificationSuccesses :exec
DELETE FROM ec2_instance_credit_modification_successes WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: PutInstanceCreditModificationSuccess :exec
INSERT INTO ec2_instance_credit_modification_successes (partition, account_id, region, token, position, instance_id) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(position), sqlc.arg(instance_id));

-- name: ListInstanceCreditModificationFailures :many
SELECT * FROM ec2_instance_credit_modification_failures WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token) ORDER BY position;

-- name: DeleteInstanceCreditModificationFailures :exec
DELETE FROM ec2_instance_credit_modification_failures WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND token = sqlc.arg(token);

-- name: PutInstanceCreditModificationFailure :exec
INSERT INTO ec2_instance_credit_modification_failures (partition, account_id, region, token, position, instance_id, error_present, error_code, error_message) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(token), sqlc.arg(position), sqlc.arg(instance_id), sqlc.arg(error_present), sqlc.arg(error_code), sqlc.arg(error_message));
