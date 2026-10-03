-- name: GetBus :one
SELECT * FROM eventbridge_buses WHERE partition=? AND account=? AND region=? AND name=?;
-- name: ListBuses :many
SELECT * FROM eventbridge_buses WHERE partition=? AND account=? AND region=? ORDER BY name;
-- name: PutBus :exec
INSERT INTO eventbridge_buses(partition,account,region,name,description,created,modified,policy,kms_key_identifier,dead_letter_arn,configuration_data_key,configuration_key_arn)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,name) DO UPDATE SET description=excluded.description,modified=excluded.modified,policy=excluded.policy,kms_key_identifier=excluded.kms_key_identifier,dead_letter_arn=excluded.dead_letter_arn,configuration_data_key=excluded.configuration_data_key,configuration_key_arn=excluded.configuration_key_arn;
-- name: DeleteBus :exec
DELETE FROM eventbridge_buses WHERE partition=? AND account=? AND region=? AND name=?;
-- name: GetBusTags :many
SELECT key,value FROM eventbridge_bus_tags WHERE partition=? AND account=? AND region=? AND bus_name=? ORDER BY key;
-- name: DeleteBusTags :exec
DELETE FROM eventbridge_bus_tags WHERE partition=? AND account=? AND region=? AND bus_name=?;
-- name: PutBusTag :exec
INSERT INTO eventbridge_bus_tags(partition,account,region,bus_name,key,value) VALUES(?,?,?,?,?,?);
-- name: GetBusPolicyPrincipals :many
SELECT arn,principal_id FROM eventbridge_bus_policy_principals WHERE partition=? AND account=? AND region=? AND bus_name=? ORDER BY arn;
-- name: DeleteBusPolicyPrincipals :exec
DELETE FROM eventbridge_bus_policy_principals WHERE partition=? AND account=? AND region=? AND bus_name=?;
-- name: PutBusPolicyPrincipal :exec
INSERT INTO eventbridge_bus_policy_principals(partition,account,region,bus_name,arn,principal_id) VALUES(?,?,?,?,?,?);
-- name: GetRule :one
SELECT * FROM eventbridge_rules WHERE partition=? AND account=? AND region=? AND bus_name=? AND name=?;
-- name: ListRules :many
SELECT * FROM eventbridge_rules WHERE partition=? AND account=? AND region=? AND bus_name=? ORDER BY name;
-- name: NextScheduledRule :one
SELECT * FROM eventbridge_rules WHERE next_schedule_seconds IS NOT NULL
ORDER BY next_schedule_seconds, 'arn:' || partition || ':events:' || region || ':' || account || ':rule/' || CASE WHEN bus_name='default' THEN name ELSE bus_name || '/' || name END LIMIT 1;
-- name: PutRule :exec
INSERT INTO eventbridge_rules(partition,account,region,bus_name,name,pattern,description,state,created_by,role_arn,has_pattern,has_description,schedule_expression,next_schedule_seconds,archive_id,encrypted_pattern,managed_by)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,bus_name,name) DO UPDATE SET pattern=excluded.pattern,description=excluded.description,state=excluded.state,role_arn=excluded.role_arn,has_pattern=excluded.has_pattern,has_description=excluded.has_description,schedule_expression=excluded.schedule_expression,next_schedule_seconds=excluded.next_schedule_seconds,archive_id=excluded.archive_id,encrypted_pattern=excluded.encrypted_pattern,managed_by=excluded.managed_by;
-- name: UpdateRuleSchedule :execrows
UPDATE eventbridge_rules SET next_schedule_seconds=? WHERE partition=? AND account=? AND region=? AND bus_name=? AND name=?;
-- name: DeleteRule :exec
DELETE FROM eventbridge_rules WHERE partition=? AND account=? AND region=? AND bus_name=? AND name=?;
-- name: GetRuleTags :many
SELECT key,value FROM eventbridge_rule_tags WHERE partition=? AND account=? AND region=? AND bus_name=? AND rule_name=? ORDER BY key;
-- name: DeleteRuleTags :exec
DELETE FROM eventbridge_rule_tags WHERE partition=? AND account=? AND region=? AND bus_name=? AND rule_name=?;
-- name: PutRuleTag :exec
INSERT INTO eventbridge_rule_tags(partition,account,region,bus_name,rule_name,key,value) VALUES(?,?,?,?,?,?,?);
-- name: ListTargets :many
SELECT * FROM eventbridge_targets WHERE partition=? AND account=? AND region=? AND bus_name=? AND rule_name=? ORDER BY id;
-- name: RuleNamesByTarget :many
SELECT DISTINCT rule_name FROM eventbridge_targets
WHERE partition=? AND account=? AND region=? AND bus_name=? AND arn=? ORDER BY rule_name;
-- name: PutTarget :exec
INSERT INTO eventbridge_targets(partition,account,region,bus_name,rule_name,id,arn,input,input_path,input_template,message_group_id,dead_letter_arn,max_retries,max_age_seconds,has_retry_policy,has_max_retries,has_max_age,role_arn,ecs_present,ecs_task_definition,ecs_task_count,ecs_launch_type,ecs_group,ecs_platform_version,ecs_reference_id,ecs_propagate_tags,ecs_enable_managed_tags,ecs_enable_execute_command,ecs_network_configuration,ecs_capacity_provider_strategy,ecs_placement_constraints,ecs_placement_strategy,ecs_tags,kinesis_partition_key_path,encrypted_configuration,http_present,http_headers,http_paths,http_query)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,bus_name,rule_name,id) DO UPDATE SET arn=excluded.arn,input=excluded.input,input_path=excluded.input_path,input_template=excluded.input_template,message_group_id=excluded.message_group_id,dead_letter_arn=excluded.dead_letter_arn,max_retries=excluded.max_retries,max_age_seconds=excluded.max_age_seconds,has_retry_policy=excluded.has_retry_policy,has_max_retries=excluded.has_max_retries,has_max_age=excluded.has_max_age,role_arn=excluded.role_arn,ecs_present=excluded.ecs_present,ecs_task_definition=excluded.ecs_task_definition,ecs_task_count=excluded.ecs_task_count,ecs_launch_type=excluded.ecs_launch_type,ecs_group=excluded.ecs_group,ecs_platform_version=excluded.ecs_platform_version,ecs_reference_id=excluded.ecs_reference_id,ecs_propagate_tags=excluded.ecs_propagate_tags,ecs_enable_managed_tags=excluded.ecs_enable_managed_tags,ecs_enable_execute_command=excluded.ecs_enable_execute_command,ecs_network_configuration=excluded.ecs_network_configuration,ecs_capacity_provider_strategy=excluded.ecs_capacity_provider_strategy,ecs_placement_constraints=excluded.ecs_placement_constraints,ecs_placement_strategy=excluded.ecs_placement_strategy,ecs_tags=excluded.ecs_tags,kinesis_partition_key_path=excluded.kinesis_partition_key_path,encrypted_configuration=excluded.encrypted_configuration,http_present=excluded.http_present,http_headers=excluded.http_headers,http_paths=excluded.http_paths,http_query=excluded.http_query;
-- name: DeleteTarget :exec
DELETE FROM eventbridge_targets WHERE partition=? AND account=? AND region=? AND bus_name=? AND rule_name=? AND id=?;
-- name: GetTargetInputPaths :many
SELECT key,path FROM eventbridge_target_input_paths WHERE partition=? AND account=? AND region=? AND bus_name=? AND rule_name=? AND target_id=? ORDER BY key;
-- name: DeleteTargetInputPaths :exec
DELETE FROM eventbridge_target_input_paths WHERE partition=? AND account=? AND region=? AND bus_name=? AND rule_name=? AND target_id=?;
-- name: PutTargetInputPath :exec
INSERT INTO eventbridge_target_input_paths(partition,account,region,bus_name,rule_name,target_id,key,path) VALUES(?,?,?,?,?,?,?,?);
-- name: GetEvent :one
SELECT * FROM eventbridge_events WHERE id=?;
-- name: PutEvent :exec
INSERT INTO eventbridge_events(id,partition,account,region,bus_name,source,detail_type,detail,event_time,accepted,producer_account,request_id,actor_arn,wire_id,wire_region,same_region_hop,cross_region_hop,replay_name,trace_header,encrypted_content,encrypted_data_key,key_arn,bus_dead_letter_arn,configuration_data_key,configuration_key_arn) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
-- name: GetEventResources :many
SELECT arn FROM eventbridge_event_resources WHERE event_id=? ORDER BY position;
-- name: PutEventResource :exec
INSERT INTO eventbridge_event_resources(event_id,position,arn) VALUES(?,?,?);
-- name: GetDelivery :one
SELECT * FROM eventbridge_deliveries WHERE id=?;
-- name: ListEventDeliveries :many
SELECT * FROM eventbridge_deliveries WHERE event_id=? ORDER BY id;
-- name: NextDelivery :one
SELECT * FROM eventbridge_deliveries WHERE state IN ('pending','dead-letter') ORDER BY due,id LIMIT 1;
-- name: PutDelivery :exec
INSERT INTO eventbridge_deliveries(id,event_id,rule_arn,target_id,target_arn,input,has_input,message_group_id,dead_letter_arn,max_retries,max_age_seconds,attempts,due,version,state,last_error_code,last_error_message,exhausted_retry_condition,role_arn,archive_id,ecs_present,ecs_task_definition,ecs_task_count,ecs_launch_type,ecs_group,ecs_platform_version,ecs_reference_id,ecs_propagate_tags,ecs_enable_managed_tags,ecs_enable_execute_command,ecs_network_configuration,ecs_capacity_provider_strategy,ecs_placement_constraints,ecs_placement_strategy,ecs_tags,kinesis_partition_key_path,bus_processing,rule_pattern,target_configuration,rule_matched,match_only,http_present,http_headers,http_paths,http_query)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET attempts=excluded.attempts,due=excluded.due,version=excluded.version,state=excluded.state,last_error_code=excluded.last_error_code,last_error_message=excluded.last_error_message,exhausted_retry_condition=excluded.exhausted_retry_condition;
