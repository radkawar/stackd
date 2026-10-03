-- name: GetImageCreation :one
SELECT * FROM ec2_image_creations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);

-- name: NextImageDeadline :one
SELECT next_action_at FROM ec2_image_creations WHERE next_action_at IS NOT NULL ORDER BY next_action_at, partition, account_id, region, resource_id LIMIT 1;

-- name: PendingImageKeys :many
SELECT partition, account_id, region, resource_id FROM ec2_image_creations WHERE next_action_at IS NOT NULL AND next_action_at <= sqlc.arg(deadline) ORDER BY partition, account_id, region, resource_id;

-- name: PutImageCreation :exec
INSERT INTO ec2_image_creations (partition, account_id, region, resource_id, instance_id, instance_generation, no_reboot, phase, next_action_at, shutdown_deadline, request_id, parent_event_id)
VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_id), sqlc.arg(instance_id), sqlc.arg(instance_generation), sqlc.arg(no_reboot), sqlc.arg(phase), sqlc.arg(next_action_at), sqlc.arg(shutdown_deadline), sqlc.arg(request_id), sqlc.arg(parent_event_id))
ON CONFLICT (partition, account_id, region, resource_id) DO UPDATE SET instance_id = excluded.instance_id, instance_generation = excluded.instance_generation, no_reboot = excluded.no_reboot, phase = excluded.phase, next_action_at = excluded.next_action_at, shutdown_deadline = excluded.shutdown_deadline, request_id = excluded.request_id, parent_event_id = excluded.parent_event_id;

-- name: DeleteImageCreation :exec
DELETE FROM ec2_image_creations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_id = sqlc.arg(resource_id);
