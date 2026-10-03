-- name: GetNodegroup :one
SELECT * FROM eks_nodegroup WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND name = ?;

-- name: ListNodegroups :many
SELECT * FROM eks_nodegroup WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? ORDER BY name;

-- name: AllNodegroups :many
SELECT * FROM eks_nodegroup ORDER BY partition, account_id, region, cluster_name, name;

-- name: PutNodegroup :exec
INSERT INTO eks_nodegroup (
 partition, account_id, region, cluster_name, name, id, cluster_id, status, operation, error_code,
 error_message, node_role_arn, node_role_id, version, release_version, ami_type, capacity_type, image_id,
 launch_template_id, launch_template_name, launch_template_version, managed_template_id, managed_template_version,
 group_name, group_arn, profile_name, client_token, request_hash, update_id, generation, template_generation,
 applied_template_generation, min_size, max_size, desired_size, disk_size, max_unavailable,
 max_unavailable_percentage, update_strategy, force, created, modified, due, deadline,
 scale_down_started, scale_down_scale_up_version,
 instance_types, subnets, labels, tags, taints
) VALUES (
 ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
 ?, ?, ?, ?, ?, ?, ?, ?,
 ?, ?, ?, ?, ?,
 ?, ?, ?, ?, ?, ?, ?, ?,
 ?, ?, ?, ?, ?, ?,
 ?, ?, ?, ?, ?, ?, ?,
 ?, ?,
 ?, ?, ?, ?, ?
)
ON CONFLICT (partition, account_id, region, cluster_name, name) DO UPDATE SET
 id = excluded.id,
 cluster_id = excluded.cluster_id,
 status = excluded.status,
 operation = excluded.operation,
 error_code = excluded.error_code,
 error_message = excluded.error_message,
 node_role_arn = excluded.node_role_arn,
 node_role_id = excluded.node_role_id,
 version = excluded.version,
 release_version = excluded.release_version,
 ami_type = excluded.ami_type,
 capacity_type = excluded.capacity_type,
 image_id = excluded.image_id,
 launch_template_id = excluded.launch_template_id,
 launch_template_name = excluded.launch_template_name,
 launch_template_version = excluded.launch_template_version,
 managed_template_id = excluded.managed_template_id,
 managed_template_version = excluded.managed_template_version,
 group_name = excluded.group_name,
 group_arn = excluded.group_arn,
 profile_name = excluded.profile_name,
 client_token = excluded.client_token,
 request_hash = excluded.request_hash,
 update_id = excluded.update_id,
 generation = excluded.generation,
 template_generation = excluded.template_generation,
 applied_template_generation = excluded.applied_template_generation,
 min_size = excluded.min_size,
 max_size = excluded.max_size,
 desired_size = excluded.desired_size,
 disk_size = excluded.disk_size,
 max_unavailable = excluded.max_unavailable,
 max_unavailable_percentage = excluded.max_unavailable_percentage,
 update_strategy = excluded.update_strategy,
 force = excluded.force,
 scale_down_started = excluded.scale_down_started,
 scale_down_scale_up_version = excluded.scale_down_scale_up_version,
 created = excluded.created,
 modified = excluded.modified,
 due = excluded.due,
 deadline = excluded.deadline,
 instance_types = excluded.instance_types,
 subnets = excluded.subnets,
 labels = excluded.labels,
 tags = excluded.tags,
 taints = excluded.taints;

-- name: DeleteNodegroup :exec
DELETE FROM eks_nodegroup WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND name = ?;

-- name: DeleteClusterNodegroups :exec
DELETE FROM eks_nodegroup WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ?;

-- name: GetNodegroupUpdate :one
SELECT * FROM eks_nodegroup_update WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND name = ? AND id = ?;

-- name: ListNodegroupUpdates :many
SELECT * FROM eks_nodegroup_update WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND name = ? ORDER BY id;

-- name: PutNodegroupUpdate :exec
INSERT INTO eks_nodegroup_update (partition, account_id, region, cluster_name, name, id, type, status, client_token, request_hash, error_code, error_message, created, version, release_version, launch_template_version, params_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, cluster_name, name, id) DO UPDATE SET
 type = excluded.type,
 status = excluded.status,
 client_token = excluded.client_token,
 request_hash = excluded.request_hash,
 error_code = excluded.error_code,
 error_message = excluded.error_message,
 created = excluded.created,
 version = excluded.version,
 release_version = excluded.release_version,
 launch_template_version = excluded.launch_template_version,
 params_json = excluded.params_json;

-- name: ListNodegroupWorkers :many
SELECT * FROM eks_nodegroup_worker WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND name = ? ORDER BY instance_id;

-- name: DeleteNodegroupWorkers :exec
DELETE FROM eks_nodegroup_worker WHERE partition = ? AND account_id = ? AND region = ? AND cluster_name = ? AND name = ?;

-- name: PutNodegroupWorker :exec
INSERT INTO eks_nodegroup_worker (partition, account_id, region, cluster_name, name, instance_id, private_ip, availability_zone, template_id, template_version, lifecycle_state, node_name, node_uid, kubelet_version, ready, unschedulable, bootstrap_started, drain_started, drain_completed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, cluster_name, name, instance_id) DO UPDATE SET
 private_ip = excluded.private_ip,
 availability_zone = excluded.availability_zone,
 template_id = excluded.template_id,
 template_version = excluded.template_version,
 lifecycle_state = excluded.lifecycle_state,
 node_name = excluded.node_name,
 node_uid = excluded.node_uid,
 kubelet_version = excluded.kubelet_version,
 ready = excluded.ready,
 unschedulable = excluded.unschedulable,
 bootstrap_started = excluded.bootstrap_started,
 drain_started = excluded.drain_started,
 drain_completed = excluded.drain_completed;

