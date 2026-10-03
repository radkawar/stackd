-- name: GetSnapshot :one
SELECT * FROM ebs_snapshots
WHERE partition = ? AND account_id = ? AND region = ? AND id = ?;

-- name: ListSnapshots :many
SELECT * FROM ebs_snapshots
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY id;

-- name: GetRegionalSnapshot :one
SELECT * FROM ebs_snapshots WHERE partition = ? AND region = ? AND id = ?;

-- name: ListAvailableSnapshots :many
SELECT s.* FROM ebs_snapshots AS s
WHERE s.partition = sqlc.arg(partition) AND s.region = sqlc.arg(region)
 AND (s.account_id = sqlc.arg(account_id) OR s.is_public = 1 OR EXISTS (
  SELECT 1 FROM ebs_snapshot_shares AS p
  WHERE p.partition = s.partition AND p.account_id = s.account_id
   AND p.region = s.region AND p.snapshot_id = s.id
   AND p.recipient_account_id = sqlc.arg(account_id) AND (p.granted = 1 OR p.readable = 1)
 )) ORDER BY s.id;

-- name: CountSnapshots :one
SELECT COUNT(*) AS total, COUNT(CASE WHEN status = 'pending' THEN 1 END) AS pending,
 COUNT(CASE WHEN status = 'pending' AND copy_source_id <> '' THEN 1 END) AS copying
FROM ebs_snapshots WHERE partition = ? AND account_id = ? AND region = ? AND deleted = 0;

-- name: GetSnapshotByToken :one
SELECT * FROM ebs_snapshots
WHERE partition = ? AND account_id = ? AND region = ? AND initial_client_token = ? AND initial_client_token <> '';

-- name: PendingSnapshotSources :many
SELECT copy_source_id AS id FROM ebs_snapshots
WHERE copy_work_at IS NOT NULL
 AND copy_source_partition = sqlc.arg(partition)
 AND copy_source_account_id = sqlc.arg(account_id)
 AND copy_source_region = sqlc.arg(region)
UNION
SELECT creation_source_id AS id FROM ebs_volumes
WHERE creation_source_id <> ''
 AND creation_source_partition = sqlc.arg(partition)
 AND creation_source_account_id = sqlc.arg(account_id)
 AND creation_source_region = sqlc.arg(region)
ORDER BY id;

-- name: VolumeSnapshotBlocksPending :one
SELECT EXISTS (
 SELECT 1 FROM ebs_snapshots
 WHERE volume_source_partition = sqlc.arg(partition)
  AND volume_source_account_id = sqlc.arg(account_id)
  AND volume_source_region = sqlc.arg(region)
  AND volume_source_id = sqlc.arg(id) AND blocks_work_at IS NOT NULL
);

-- name: NextWork :one
WITH deadlines AS (
 SELECT partition, account_id, region, id, delete_at AS due FROM ebs_snapshots
 WHERE deleted = 1 AND delete_at IS NOT NULL AND copy_work_at IS NULL AND blocks_work_at IS NULL
 UNION ALL
 SELECT partition, account_id, region, id, complete_at AS due FROM ebs_snapshots
 WHERE deleted = 0 AND status = 'pending' AND sealed = 1 AND complete_at IS NOT NULL AND copy_work_at IS NULL AND blocks_work_at IS NULL
 UNION ALL
 SELECT partition, account_id, region, id, timeout_at AS due FROM ebs_snapshots
 WHERE deleted = 0 AND status = 'pending' AND sealed = 0 AND timeout_at IS NOT NULL AND copy_work_at IS NULL AND blocks_work_at IS NULL
 UNION ALL
 SELECT partition, account_id, region, id, readable_at AS due FROM ebs_snapshots
 WHERE deleted = 0 AND status = 'completed' AND readable = 0 AND readable_at IS NOT NULL AND copy_work_at IS NULL AND blocks_work_at IS NULL
 UNION ALL
 SELECT partition, account_id, region, id, sharing_at AS due FROM ebs_snapshots
 WHERE deleted = 0 AND sharing_at IS NOT NULL AND copy_work_at IS NULL AND blocks_work_at IS NULL
 UNION ALL
 SELECT partition, account_id, region, id, native_work_at AS due FROM ebs_snapshots
 WHERE native_backup_path <> '' AND native_work_at IS NOT NULL AND copy_work_at IS NULL AND blocks_work_at IS NULL
 UNION ALL
 SELECT partition, account_id, region, id, copy_work_at AS due FROM ebs_snapshots
 WHERE copy_work_at IS NOT NULL
 UNION ALL
 SELECT partition, account_id, region, id, blocks_work_at AS due FROM ebs_snapshots
 WHERE blocks_work_at IS NOT NULL
)
SELECT s.* FROM ebs_snapshots AS s JOIN (
 SELECT partition, account_id, region, id FROM deadlines
 ORDER BY due, partition, account_id, region, id LIMIT 1
) AS work USING (partition, account_id, region, id);

-- name: PutSnapshot :exec
INSERT INTO ebs_snapshots (
 partition, account_id, region, id, parent_id, lineage_id,
 initial_client_token, initial_description, initial_encrypted, initial_kms_key_arn,
 initial_parent_snapshot_id, initial_timeout, initial_volume_size, initial_tags_present,
 created, status, sealed, readable, deleted, complete_at, readable_at, timeout_at, delete_at,
 state_message, tags_present, kms_key_arn, wrapped_key, token_key, is_public, sharing_at,
 volume_size, description, copy_source_partition, copy_source_account_id, copy_source_region,
 copy_source_id, copy_incremental, copy_completion_duration_minutes,
 copy_request_id, copy_parent_event_id,
 volume_source_partition, volume_source_account_id, volume_source_region,
 volume_source_id, volume_request_id, volume_parent_event_id,
 native_backup_path, native_backup_ready, native_work_at,
 copy_work_at, copy_key_source_partition, copy_key_source_account_id, copy_key_source_region,
 copy_key_source_id, copy_source_grant_token, copy_destination_grant_token, copy_destination_encrypt_grant_token,
 blocks_work_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
 ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, id) DO UPDATE SET
 parent_id = excluded.parent_id, lineage_id = excluded.lineage_id,
 initial_client_token = excluded.initial_client_token, initial_description = excluded.initial_description,
 initial_encrypted = excluded.initial_encrypted, initial_kms_key_arn = excluded.initial_kms_key_arn,
 initial_parent_snapshot_id = excluded.initial_parent_snapshot_id,
 initial_timeout = excluded.initial_timeout, initial_volume_size = excluded.initial_volume_size,
 initial_tags_present = excluded.initial_tags_present,
 created = excluded.created, status = excluded.status, sealed = excluded.sealed,
 readable = excluded.readable, deleted = excluded.deleted, complete_at = excluded.complete_at,
 readable_at = excluded.readable_at, timeout_at = excluded.timeout_at, delete_at = excluded.delete_at,
 state_message = excluded.state_message, tags_present = excluded.tags_present,
 kms_key_arn = excluded.kms_key_arn, wrapped_key = excluded.wrapped_key, token_key = excluded.token_key,
 is_public = excluded.is_public, sharing_at = excluded.sharing_at,
 volume_size = excluded.volume_size, description = excluded.description,
 copy_source_partition = excluded.copy_source_partition, copy_source_account_id = excluded.copy_source_account_id,
 copy_source_region = excluded.copy_source_region, copy_source_id = excluded.copy_source_id,
 copy_incremental = excluded.copy_incremental,
 copy_completion_duration_minutes = excluded.copy_completion_duration_minutes,
 copy_request_id = excluded.copy_request_id, copy_parent_event_id = excluded.copy_parent_event_id,
 volume_source_partition = excluded.volume_source_partition, volume_source_account_id = excluded.volume_source_account_id,
 volume_source_region = excluded.volume_source_region, volume_source_id = excluded.volume_source_id,
 volume_request_id = excluded.volume_request_id, volume_parent_event_id = excluded.volume_parent_event_id,
 native_backup_path = excluded.native_backup_path, native_backup_ready = excluded.native_backup_ready,
 native_work_at = excluded.native_work_at,
 copy_work_at = excluded.copy_work_at, copy_key_source_partition = excluded.copy_key_source_partition,
 copy_key_source_account_id = excluded.copy_key_source_account_id,
 copy_key_source_region = excluded.copy_key_source_region, copy_key_source_id = excluded.copy_key_source_id,
 copy_source_grant_token = excluded.copy_source_grant_token,
 copy_destination_grant_token = excluded.copy_destination_grant_token,
 copy_destination_encrypt_grant_token = excluded.copy_destination_encrypt_grant_token,
 blocks_work_at = excluded.blocks_work_at;

-- name: DeleteSnapshot :execrows
DELETE FROM ebs_snapshots WHERE partition = ? AND account_id = ? AND region = ? AND id = ?;

-- name: ListInitialTags :many
SELECT key, value FROM ebs_initial_tags
WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ? ORDER BY position;

-- name: DeleteInitialTags :exec
DELETE FROM ebs_initial_tags WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ?;

-- name: PutInitialTag :exec
INSERT INTO ebs_initial_tags (partition, account_id, region, snapshot_id, position, key, value)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListTags :many
SELECT key, value FROM ebs_snapshot_tags
WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ? ORDER BY key;

-- name: DeleteTags :exec
DELETE FROM ebs_snapshot_tags WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ?;

-- name: PutTag :exec
INSERT INTO ebs_snapshot_tags (partition, account_id, region, snapshot_id, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetBlock :one
SELECT b.checksum, b.written_snapshot_id, b.encryption_origin_partition,
 b.encryption_origin_account_id, b.encryption_origin_region, b.encryption_origin_id, p.data FROM ebs_blocks AS b
JOIN ebs_block_payloads AS p USING (partition, account_id, region, snapshot_id, block_index)
WHERE b.partition = ? AND b.account_id = ? AND b.region = ? AND b.snapshot_id = ? AND b.block_index = ?;

-- name: ListBlocks :many
SELECT block_index, checksum, written_snapshot_id, encryption_origin_partition,
 encryption_origin_account_id, encryption_origin_region, encryption_origin_id FROM ebs_blocks
WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ? ORDER BY block_index;

-- name: PutBlock :exec
INSERT INTO ebs_blocks (partition, account_id, region, snapshot_id, block_index, checksum, written_snapshot_id,
 encryption_origin_partition, encryption_origin_account_id, encryption_origin_region, encryption_origin_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, snapshot_id, block_index) DO UPDATE
SET checksum = excluded.checksum, written_snapshot_id = excluded.written_snapshot_id,
 encryption_origin_partition = excluded.encryption_origin_partition,
 encryption_origin_account_id = excluded.encryption_origin_account_id,
 encryption_origin_region = excluded.encryption_origin_region, encryption_origin_id = excluded.encryption_origin_id;

-- name: PutBlockPayload :exec
INSERT INTO ebs_block_payloads (partition, account_id, region, snapshot_id, block_index, data)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, snapshot_id, block_index) DO UPDATE SET data = excluded.data;

-- name: DeleteBlocks :exec
DELETE FROM ebs_blocks WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ?;

-- name: GetEncryptionDefault :one
SELECT enabled, kms_key_id FROM ebs_encryption_defaults
WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutEncryptionDefault :exec
INSERT INTO ebs_encryption_defaults (partition, account_id, region, enabled, kms_key_id)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region) DO UPDATE SET enabled = excluded.enabled, kms_key_id = excluded.kms_key_id;

-- name: GetSequence :one
SELECT sequence FROM ebs_sequences WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutSequence :exec
INSERT INTO ebs_sequences (partition, account_id, region, sequence) VALUES (?, ?, ?, ?)
ON CONFLICT(partition, account_id, region) DO UPDATE SET sequence = excluded.sequence;

-- name: ListShares :many
SELECT recipient_account_id, granted, readable FROM ebs_snapshot_shares
WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ? ORDER BY recipient_account_id;

-- name: DeleteShares :exec
DELETE FROM ebs_snapshot_shares WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ?;

-- name: PutShare :exec
INSERT INTO ebs_snapshot_shares (partition, account_id, region, snapshot_id, recipient_account_id, granted, readable)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetSnapshotPublicAccess :one
SELECT state FROM ebs_snapshot_public_access WHERE partition = ? AND account_id = ? AND region = ?;

-- name: PutSnapshotPublicAccess :exec
INSERT INTO ebs_snapshot_public_access (partition, account_id, region, state) VALUES (?, ?, ?, ?)
ON CONFLICT(partition, account_id, region) DO UPDATE SET state = excluded.state;

-- name: ListSharedTags :many
SELECT key, value FROM ebs_snapshot_shared_tags
WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ? AND recipient_account_id = ? ORDER BY key;

-- name: DeleteSharedTags :exec
DELETE FROM ebs_snapshot_shared_tags
WHERE partition = ? AND account_id = ? AND region = ? AND snapshot_id = ? AND recipient_account_id = ?;

-- name: PutSharedTag :exec
INSERT INTO ebs_snapshot_shared_tags (partition, account_id, region, snapshot_id, recipient_account_id, key, value)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListAccountTags :many
SELECT t.partition, t.account_id, t.region, t.snapshot_id, t.key, t.value
FROM ebs_snapshot_tags AS t JOIN ebs_snapshots AS s
 ON s.partition = t.partition AND s.account_id = t.account_id AND s.region = t.region AND s.id = t.snapshot_id
WHERE t.partition = sqlc.arg(partition) AND t.region = sqlc.arg(region) AND t.account_id = sqlc.arg(account_id) AND s.deleted = 0
UNION ALL
SELECT t.partition, t.account_id, t.region, t.snapshot_id, t.key, t.value
FROM ebs_snapshot_shared_tags AS t JOIN ebs_snapshots AS s
 ON s.partition = t.partition AND s.account_id = t.account_id AND s.region = t.region AND s.id = t.snapshot_id
WHERE t.partition = sqlc.arg(partition) AND t.region = sqlc.arg(region) AND t.recipient_account_id = sqlc.arg(account_id) AND s.deleted = 0
ORDER BY snapshot_id, key;

-- name: GetVolume :one
SELECT * FROM ebs_volumes
WHERE partition = ? AND account_id = ? AND region = ? AND id = ?;

-- name: ListVolumes :many
SELECT * FROM ebs_volumes
WHERE partition = ? AND account_id = ? AND region = ? ORDER BY id;

-- name: GetVolumeByToken :one
SELECT * FROM ebs_volumes
WHERE partition = ? AND account_id = ? AND region = ? AND client_token = ? AND client_token <> '';

-- name: NextVolumeWork :one
WITH deadlines AS (
 SELECT partition, account_id, region, id, transition_at AS due FROM ebs_volumes
 WHERE status <> 'deleted' AND transition_at IS NOT NULL
 UNION ALL
 SELECT partition, account_id, region, id, modification_optimizing_at AS due FROM ebs_volumes
 WHERE status <> 'deleted' AND modification_present = 1 AND modification_state = 'modifying'
  AND modification_optimizing_at IS NOT NULL
 UNION ALL
 SELECT partition, account_id, region, id, modification_completed_at AS due FROM ebs_volumes
 WHERE status <> 'deleted' AND modification_present = 1 AND modification_state = 'optimizing'
  AND modification_completed_at IS NOT NULL
)
SELECT v.* FROM ebs_volumes AS v JOIN (
 SELECT partition, account_id, region, id FROM deadlines
 ORDER BY due, partition, account_id, region, id LIMIT 1
) AS work USING (partition, account_id, region, id);

-- name: PutVolume :exec
INSERT INTO ebs_volumes (
 partition, account_id, region, id, size, volume_type, iops, throughput, multi_attach,
 zone_name, zone_id, snapshot_id, lineage_id, created, transition_at, snapshot_at, status, state_message,
 auto_enable_io, initialization_rate, tags_present, encrypted, kms_key_arn, wrapped_key,
 native_path, service_grant_id, infrastructure_grant_id,
 modification_status_message,
 creation_input, client_token, request_id, parent_event_id, modification_present,
 modification_original_size, modification_original_type, modification_original_iops,
 modification_original_throughput, modification_original_multi_attach,
 modification_target_size, modification_target_type, modification_target_iops,
 modification_target_throughput, modification_target_multi_attach,
 modification_started, modification_optimizing_at, modification_completed_at,
 modification_state, modification_request_id, modification_parent_event_id,
 creation_source_partition, creation_source_account_id, creation_source_region, creation_source_id,
 creation_source_wrapped_key, creation_reuse_source_ciphertext, creation_retire_grant
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
 , ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT(partition, account_id, region, id) DO UPDATE SET
 size = excluded.size, volume_type = excluded.volume_type, iops = excluded.iops,
 throughput = excluded.throughput, multi_attach = excluded.multi_attach,
 zone_name = excluded.zone_name, zone_id = excluded.zone_id,
 snapshot_id = excluded.snapshot_id, lineage_id = excluded.lineage_id,
 created = excluded.created, transition_at = excluded.transition_at, snapshot_at = excluded.snapshot_at,
 status = excluded.status, state_message = excluded.state_message,
 auto_enable_io = excluded.auto_enable_io, initialization_rate = excluded.initialization_rate,
 tags_present = excluded.tags_present, encrypted = excluded.encrypted, kms_key_arn = excluded.kms_key_arn,
 wrapped_key = excluded.wrapped_key, creation_input = excluded.creation_input,
 native_path = excluded.native_path, service_grant_id = excluded.service_grant_id,
 infrastructure_grant_id = excluded.infrastructure_grant_id,
 modification_status_message = excluded.modification_status_message,
 client_token = excluded.client_token, request_id = excluded.request_id,
 parent_event_id = excluded.parent_event_id, modification_present = excluded.modification_present,
 modification_original_size = excluded.modification_original_size,
 modification_original_type = excluded.modification_original_type,
 modification_original_iops = excluded.modification_original_iops,
 modification_original_throughput = excluded.modification_original_throughput,
 modification_original_multi_attach = excluded.modification_original_multi_attach,
 modification_target_size = excluded.modification_target_size,
 modification_target_type = excluded.modification_target_type,
 modification_target_iops = excluded.modification_target_iops,
 modification_target_throughput = excluded.modification_target_throughput,
 modification_target_multi_attach = excluded.modification_target_multi_attach,
 modification_started = excluded.modification_started,
 modification_optimizing_at = excluded.modification_optimizing_at,
 modification_completed_at = excluded.modification_completed_at,
 modification_state = excluded.modification_state,
 modification_request_id = excluded.modification_request_id,
 modification_parent_event_id = excluded.modification_parent_event_id,
 creation_source_partition = excluded.creation_source_partition,
 creation_source_account_id = excluded.creation_source_account_id,
 creation_source_region = excluded.creation_source_region, creation_source_id = excluded.creation_source_id,
 creation_source_wrapped_key = excluded.creation_source_wrapped_key,
 creation_reuse_source_ciphertext = excluded.creation_reuse_source_ciphertext,
 creation_retire_grant = excluded.creation_retire_grant;

-- name: ListVolumeTags :many
SELECT key, value FROM ebs_volume_tags
WHERE partition = ? AND account_id = ? AND region = ? AND volume_id = ? ORDER BY key;

-- name: DeleteVolumeTags :exec
DELETE FROM ebs_volume_tags WHERE partition = ? AND account_id = ? AND region = ? AND volume_id = ?;

-- name: PutVolumeTag :exec
INSERT INTO ebs_volume_tags (partition, account_id, region, volume_id, key, value)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetVolumeBlock :one
SELECT b.checksum, b.written_snapshot_id, b.encryption_origin_partition,
 b.encryption_origin_account_id, b.encryption_origin_region, b.encryption_origin_id, p.data FROM ebs_volume_blocks AS b
JOIN ebs_volume_block_payloads AS p USING (partition, account_id, region, volume_id, block_index)
WHERE b.partition = ? AND b.account_id = ? AND b.region = ? AND b.volume_id = ? AND b.block_index = ?;

-- name: ListVolumeBlocks :many
SELECT block_index, checksum, written_snapshot_id, encryption_origin_partition,
 encryption_origin_account_id, encryption_origin_region, encryption_origin_id FROM ebs_volume_blocks
WHERE partition = ? AND account_id = ? AND region = ? AND volume_id = ? ORDER BY block_index;

-- name: PutVolumeBlock :exec
INSERT INTO ebs_volume_blocks (partition, account_id, region, volume_id, block_index, checksum, written_snapshot_id,
 encryption_origin_partition, encryption_origin_account_id, encryption_origin_region, encryption_origin_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, volume_id, block_index) DO UPDATE
SET checksum = excluded.checksum, written_snapshot_id = excluded.written_snapshot_id,
 encryption_origin_partition = excluded.encryption_origin_partition,
 encryption_origin_account_id = excluded.encryption_origin_account_id,
 encryption_origin_region = excluded.encryption_origin_region, encryption_origin_id = excluded.encryption_origin_id;

-- name: PutVolumeBlockPayload :exec
INSERT INTO ebs_volume_block_payloads (partition, account_id, region, volume_id, block_index, data)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, volume_id, block_index) DO UPDATE SET data = excluded.data;

-- name: DeleteVolumeBlocks :exec
DELETE FROM ebs_volume_blocks WHERE partition = ? AND account_id = ? AND region = ? AND volume_id = ?;

-- name: ListVolumeModificationStarts :many
SELECT started FROM ebs_volume_modification_starts
WHERE partition = ? AND account_id = ? AND region = ? AND volume_id = ? ORDER BY position;

-- name: DeleteVolumeModificationStarts :exec
DELETE FROM ebs_volume_modification_starts
WHERE partition = ? AND account_id = ? AND region = ? AND volume_id = ?;

-- name: PutVolumeModificationStart :exec
INSERT INTO ebs_volume_modification_starts (partition, account_id, region, volume_id, position, started)
VALUES (?, ?, ?, ?, ?, ?);
