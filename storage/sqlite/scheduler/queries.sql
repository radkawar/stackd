-- name: PutGroup :exec
INSERT INTO scheduler_groups (partition,account,region,name,arn,created,modified,client_token) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(arn) DO UPDATE SET partition=excluded.partition,account=excluded.account,region=excluded.region,name=excluded.name,created=excluded.created,modified=excluded.modified,client_token=excluded.client_token;

-- name: GetGroup :one
SELECT * FROM scheduler_groups WHERE arn=?;

-- name: DeleteGroup :exec
DELETE FROM scheduler_groups WHERE arn=?;

-- name: PutSchedule :exec
INSERT INTO scheduler_schedules (partition,account,region,group_name,name,arn,created,modified,expression,timezone,state,description,has_description,action_after_completion,start,end,next,window_mode,window_minutes,has_window_minutes,kms_key_arn,ciphertext,data_key,revision,create_token,update_token,create_hash,update_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(arn) DO UPDATE SET partition=excluded.partition,account=excluded.account,region=excluded.region,group_name=excluded.group_name,name=excluded.name,created=excluded.created,modified=excluded.modified,expression=excluded.expression,timezone=excluded.timezone,state=excluded.state,description=excluded.description,has_description=excluded.has_description,action_after_completion=excluded.action_after_completion,start=excluded.start,end=excluded.end,next=excluded.next,window_mode=excluded.window_mode,window_minutes=excluded.window_minutes,has_window_minutes=excluded.has_window_minutes,kms_key_arn=excluded.kms_key_arn,ciphertext=excluded.ciphertext,data_key=excluded.data_key,revision=excluded.revision,create_token=excluded.create_token,update_token=excluded.update_token,create_hash=excluded.create_hash,update_hash=excluded.update_hash;

-- name: GetSchedule :one
SELECT * FROM scheduler_schedules WHERE arn=?;

-- name: DeleteSchedule :exec
DELETE FROM scheduler_schedules WHERE arn=?;

-- name: PutDelivery :exec
INSERT INTO scheduler_deliveries (id,partition,account,region,group_name,schedule_name,schedule_arn,revision,scheduled,due,expires,kms_key_arn,ciphertext,data_key,attempts,phase,last_error_code,last_error_message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET partition=excluded.partition,account=excluded.account,region=excluded.region,group_name=excluded.group_name,schedule_name=excluded.schedule_name,schedule_arn=excluded.schedule_arn,revision=excluded.revision,scheduled=excluded.scheduled,due=excluded.due,expires=excluded.expires,kms_key_arn=excluded.kms_key_arn,ciphertext=excluded.ciphertext,data_key=excluded.data_key,attempts=excluded.attempts,phase=excluded.phase,last_error_code=excluded.last_error_code,last_error_message=excluded.last_error_message;

-- name: GetDelivery :one
SELECT * FROM scheduler_deliveries WHERE id=?;

-- name: DeleteDelivery :exec
DELETE FROM scheduler_deliveries WHERE id=?;

-- name: PutTarget :exec
INSERT INTO scheduler_targets (owner_id,arn,role_arn,input,dead_letter_arn,has_input,max_age_seconds,max_retries,message_group_id,event_source,event_detail_type,partition_key,has_sqs,has_event_bridge,has_kinesis) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_id) DO UPDATE SET arn=excluded.arn,role_arn=excluded.role_arn,input=excluded.input,dead_letter_arn=excluded.dead_letter_arn,has_input=excluded.has_input,max_age_seconds=excluded.max_age_seconds,max_retries=excluded.max_retries,message_group_id=excluded.message_group_id,event_source=excluded.event_source,event_detail_type=excluded.event_detail_type,partition_key=excluded.partition_key,has_sqs=excluded.has_sqs,has_event_bridge=excluded.has_event_bridge,has_kinesis=excluded.has_kinesis;

-- name: GetTarget :one
SELECT * FROM scheduler_targets WHERE owner_id=?;

-- name: DeleteTarget :exec
DELETE FROM scheduler_targets WHERE owner_id=?;

-- name: PutEcs :exec
INSERT INTO scheduler_ecs (owner_id,task_definition_arn,group_name,launch_type,platform_version,propagate_tags,reference_id,task_count,has_task_count,managed_tags,execute_command,has_managed_tags,has_execute_command,has_network,assign_public_ip) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_id) DO UPDATE SET task_definition_arn=excluded.task_definition_arn,group_name=excluded.group_name,launch_type=excluded.launch_type,platform_version=excluded.platform_version,propagate_tags=excluded.propagate_tags,reference_id=excluded.reference_id,task_count=excluded.task_count,has_task_count=excluded.has_task_count,managed_tags=excluded.managed_tags,execute_command=excluded.execute_command,has_managed_tags=excluded.has_managed_tags,has_execute_command=excluded.has_execute_command,has_network=excluded.has_network,assign_public_ip=excluded.assign_public_ip;

-- name: GetEcs :one
SELECT * FROM scheduler_ecs WHERE owner_id=?;

-- name: DeleteEcs :exec
DELETE FROM scheduler_ecs WHERE owner_id=?;

-- name: PutGroupTags :exec
INSERT INTO scheduler_group_tags (group_arn,key,value) VALUES (?,?,?) ON CONFLICT(group_arn,key) DO UPDATE SET value=excluded.value;

-- name: GetGroupTags :many
SELECT * FROM scheduler_group_tags WHERE group_arn=? ORDER BY key;

-- name: DeleteGroupTags :exec
DELETE FROM scheduler_group_tags WHERE group_arn=?;

-- name: PutEcsSubnets :exec
INSERT INTO scheduler_ecs_subnets (owner_id,position,value) VALUES (?,?,?) ON CONFLICT(owner_id,position) DO UPDATE SET value=excluded.value;

-- name: GetEcsSubnets :many
SELECT * FROM scheduler_ecs_subnets WHERE owner_id=? ORDER BY position;

-- name: DeleteEcsSubnets :exec
DELETE FROM scheduler_ecs_subnets WHERE owner_id=?;

-- name: PutEcsSecurityGroups :exec
INSERT INTO scheduler_ecs_security_groups (owner_id,position,value) VALUES (?,?,?) ON CONFLICT(owner_id,position) DO UPDATE SET value=excluded.value;

-- name: GetEcsSecurityGroups :many
SELECT * FROM scheduler_ecs_security_groups WHERE owner_id=? ORDER BY position;

-- name: DeleteEcsSecurityGroups :exec
DELETE FROM scheduler_ecs_security_groups WHERE owner_id=?;

-- name: PutEcsCapacity :exec
INSERT INTO scheduler_ecs_capacity (owner_id,position,name,base,weight,has_base,has_weight) VALUES (?,?,?,?,?,?,?) ON CONFLICT(owner_id,position) DO UPDATE SET name=excluded.name,base=excluded.base,weight=excluded.weight,has_base=excluded.has_base,has_weight=excluded.has_weight;

-- name: GetEcsCapacity :many
SELECT * FROM scheduler_ecs_capacity WHERE owner_id=? ORDER BY position;

-- name: DeleteEcsCapacity :exec
DELETE FROM scheduler_ecs_capacity WHERE owner_id=?;

-- name: PutEcsConstraints :exec
INSERT INTO scheduler_ecs_constraints (owner_id,position,type,expression) VALUES (?,?,?,?) ON CONFLICT(owner_id,position) DO UPDATE SET type=excluded.type,expression=excluded.expression;

-- name: GetEcsConstraints :many
SELECT * FROM scheduler_ecs_constraints WHERE owner_id=? ORDER BY position;

-- name: DeleteEcsConstraints :exec
DELETE FROM scheduler_ecs_constraints WHERE owner_id=?;

-- name: PutEcsPlacement :exec
INSERT INTO scheduler_ecs_placement (owner_id,position,type,field) VALUES (?,?,?,?) ON CONFLICT(owner_id,position) DO UPDATE SET type=excluded.type,field=excluded.field;

-- name: GetEcsPlacement :many
SELECT * FROM scheduler_ecs_placement WHERE owner_id=? ORDER BY position;

-- name: DeleteEcsPlacement :exec
DELETE FROM scheduler_ecs_placement WHERE owner_id=?;

-- name: PutEcsTags :exec
INSERT INTO scheduler_ecs_tags (owner_id,position,key,value) VALUES (?,?,?,?) ON CONFLICT(owner_id,position) DO UPDATE SET key=excluded.key,value=excluded.value;

-- name: GetEcsTags :many
SELECT * FROM scheduler_ecs_tags WHERE owner_id=? ORDER BY position;

-- name: DeleteEcsTags :exec
DELETE FROM scheduler_ecs_tags WHERE owner_id=?;

-- name: ListGroups :many
SELECT * FROM scheduler_groups WHERE partition=? AND account=? AND region=? ORDER BY name;

-- name: ListSchedules :many
SELECT * FROM scheduler_schedules WHERE partition=? AND account=? AND region=? ORDER BY group_name,name;

-- name: NextSchedule :one
SELECT * FROM scheduler_schedules WHERE next IS NOT NULL ORDER BY next,arn LIMIT 1;

-- name: NextDelivery :one
SELECT * FROM scheduler_deliveries ORDER BY due,id LIMIT 1;

-- name: ScheduleDeliveries :many
SELECT id FROM scheduler_deliveries WHERE schedule_arn=? ORDER BY id;

-- name: GroupDeliveries :many
SELECT id FROM scheduler_deliveries WHERE partition=? AND account=? AND region=? AND group_name=? ORDER BY id;
