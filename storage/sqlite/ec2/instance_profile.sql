-- name: GetInstanceProfileAssociation :one
SELECT * FROM ec2_instance_profile_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListInstanceProfileAssociations :many
SELECT * FROM ec2_instance_profile_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY resource_id;

-- name: PendingInstanceProfileAssociations :many
SELECT * FROM ec2_instance_profile_associations WHERE next_action_at <= sqlc.arg(deadline) ORDER BY partition, account_id, region, resource_id;

-- name: NextInstanceProfileAssociationDeadline :one
SELECT next_action_at FROM ec2_instance_profile_associations WHERE next_action_at IS NOT NULL ORDER BY next_action_at LIMIT 1;

-- name: PutInstanceProfileAssociation :exec
INSERT INTO ec2_instance_profile_associations (partition, account_id, region, resource_id, instance_id, profile_arn, profile_id, state, timestamp, next_action_at, credential_id_v1, credential_id_v2)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(instance_id), sqlc.arg(profile_arn), sqlc.arg(profile_id), sqlc.arg(state), sqlc.arg(timestamp), sqlc.arg(next_action_at), sqlc.arg(credential_id_v1), sqlc.arg(credential_id_v2))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET instance_id = excluded.instance_id, profile_arn = excluded.profile_arn, profile_id = excluded.profile_id, state = excluded.state, timestamp = excluded.timestamp, next_action_at = excluded.next_action_at, credential_id_v1 = excluded.credential_id_v1, credential_id_v2 = excluded.credential_id_v2;

-- name: DeleteInstanceProfileAssociation :execrows
DELETE FROM ec2_instance_profile_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: ListInstanceMetadataDevices :many
SELECT device_name FROM ec2_instance_metadata_devices WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id) ORDER BY position;

-- name: PutInstanceMetadataDevice :exec
INSERT INTO ec2_instance_metadata_devices (partition, account_id, region, resource_id, position, device_name)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(position), sqlc.arg(device_name));

-- name: DeleteInstanceMetadataDevices :exec
DELETE FROM ec2_instance_metadata_devices WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);
