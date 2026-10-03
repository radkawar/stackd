-- name: WFWorkflowPut :exec
INSERT INTO glue_workflow (partition, account_id, region, name, description, created, modified, max_concurrent) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(description), sqlc.arg(created), sqlc.arg(modified), sqlc.arg(max_concurrent))
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET description = excluded.description, created = excluded.created, modified = excluded.modified, max_concurrent = excluded.max_concurrent;

-- name: WFWorkflowDelete :exec
DELETE FROM glue_workflow WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFWorkflowList :many
SELECT * FROM glue_workflow WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY partition, account_id, region, name;

-- name: WFWorkflowGet :one
SELECT * FROM glue_workflow WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFWorkflowTagPut :exec
INSERT INTO glue_workflow_tag (partition, account_id, region, name, item_key, item_value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(item_key), sqlc.arg(item_value))
ON CONFLICT (partition, account_id, region, name, item_key) DO UPDATE SET item_value = excluded.item_value;

-- name: WFWorkflowTagDelete :exec
DELETE FROM glue_workflow_tag WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFWorkflowTagList :many
SELECT * FROM glue_workflow_tag WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY partition, account_id, region, name, item_key;

-- name: WFWorkflowPropertyPut :exec
INSERT INTO glue_workflow_property (partition, account_id, region, name, item_key, item_value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(item_key), sqlc.arg(item_value))
ON CONFLICT (partition, account_id, region, name, item_key) DO UPDATE SET item_value = excluded.item_value;

-- name: WFWorkflowPropertyDelete :exec
DELETE FROM glue_workflow_property WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFWorkflowPropertyList :many
SELECT * FROM glue_workflow_property WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY partition, account_id, region, name, item_key;

-- name: WFTriggerPut :exec
INSERT INTO glue_trigger (partition, account_id, region, name, trigger_type, state, description, schedule, workflow_name, predicate_logical, predicate_present, next_fire) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(trigger_type), sqlc.arg(state), sqlc.arg(description), sqlc.arg(schedule), sqlc.arg(workflow_name), sqlc.arg(predicate_logical), sqlc.arg(predicate_present), sqlc.arg(next_fire))
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET trigger_type = excluded.trigger_type, state = excluded.state, description = excluded.description, schedule = excluded.schedule, workflow_name = excluded.workflow_name, predicate_logical = excluded.predicate_logical, predicate_present = excluded.predicate_present, next_fire = excluded.next_fire;

-- name: WFTriggerDelete :exec
DELETE FROM glue_trigger WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFTriggerList :many
SELECT * FROM glue_trigger WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY partition, account_id, region, name;

-- name: WFTriggerGet :one
SELECT * FROM glue_trigger WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFTriggerTagPut :exec
INSERT INTO glue_trigger_tag (partition, account_id, region, name, item_key, item_value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(item_key), sqlc.arg(item_value))
ON CONFLICT (partition, account_id, region, name, item_key) DO UPDATE SET item_value = excluded.item_value;

-- name: WFTriggerTagDelete :exec
DELETE FROM glue_trigger_tag WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFTriggerTagList :many
SELECT * FROM glue_trigger_tag WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY partition, account_id, region, name, item_key;

-- name: WFTriggerActionPut :exec
INSERT INTO glue_trigger_action (partition, account_id, region, name, ordinal, job_name, crawler_name, security_configuration, timeout, notification_delay) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(ordinal), sqlc.arg(job_name), sqlc.arg(crawler_name), sqlc.arg(security_configuration), sqlc.arg(timeout), sqlc.arg(notification_delay))
ON CONFLICT (partition, account_id, region, name, ordinal) DO UPDATE SET job_name = excluded.job_name, crawler_name = excluded.crawler_name, security_configuration = excluded.security_configuration, timeout = excluded.timeout, notification_delay = excluded.notification_delay;

-- name: WFTriggerActionDelete :exec
DELETE FROM glue_trigger_action WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFTriggerActionList :many
SELECT * FROM glue_trigger_action WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY ordinal;

-- name: WFTriggerArgumentPut :exec
INSERT INTO glue_trigger_argument (partition, account_id, region, name, ordinal, item_key, item_value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(ordinal), sqlc.arg(item_key), sqlc.arg(item_value))
ON CONFLICT (partition, account_id, region, name, ordinal, item_key) DO UPDATE SET item_value = excluded.item_value;

-- name: WFTriggerArgumentDelete :exec
DELETE FROM glue_trigger_argument WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND ordinal = sqlc.arg(ordinal);

-- name: WFTriggerArgumentList :many
SELECT * FROM glue_trigger_argument WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND ordinal = sqlc.arg(ordinal) ORDER BY ordinal;

-- name: WFTriggerConditionPut :exec
INSERT INTO glue_trigger_condition (partition, account_id, region, name, ordinal, job_name, crawler_name, state, crawl_state, logical_operator) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(ordinal), sqlc.arg(job_name), sqlc.arg(crawler_name), sqlc.arg(state), sqlc.arg(crawl_state), sqlc.arg(logical_operator))
ON CONFLICT (partition, account_id, region, name, ordinal) DO UPDATE SET job_name = excluded.job_name, crawler_name = excluded.crawler_name, state = excluded.state, crawl_state = excluded.crawl_state, logical_operator = excluded.logical_operator;

-- name: WFTriggerConditionDelete :exec
DELETE FROM glue_trigger_condition WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFTriggerConditionList :many
SELECT * FROM glue_trigger_condition WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY ordinal;

-- name: WFSecurityConfigurationPut :exec
INSERT INTO glue_security_configuration (partition, account_id, region, name, created, s3_mode, s3_key, logs_mode, logs_key, bookmarks_mode, bookmarks_key) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(created), sqlc.arg(s3_mode), sqlc.arg(s3_key), sqlc.arg(logs_mode), sqlc.arg(logs_key), sqlc.arg(bookmarks_mode), sqlc.arg(bookmarks_key))
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET created = excluded.created, s3_mode = excluded.s3_mode, s3_key = excluded.s3_key, logs_mode = excluded.logs_mode, logs_key = excluded.logs_key, bookmarks_mode = excluded.bookmarks_mode, bookmarks_key = excluded.bookmarks_key;

-- name: WFSecurityConfigurationDelete :exec
DELETE FROM glue_security_configuration WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFSecurityConfigurationList :many
SELECT * FROM glue_security_configuration WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY partition, account_id, region, name;

-- name: WFSecurityConfigurationGet :one
SELECT * FROM glue_security_configuration WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name);

-- name: WFWorkflowRunPut :exec
INSERT INTO glue_workflow_run (partition, account_id, region, name, run_id, previous_run_id, root_trigger, status, error, started, completed, next_poll) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(run_id), sqlc.arg(previous_run_id), sqlc.arg(root_trigger), sqlc.arg(status), sqlc.arg(error), sqlc.arg(started), sqlc.arg(completed), sqlc.arg(next_poll))
ON CONFLICT (partition, account_id, region, name, run_id) DO UPDATE SET previous_run_id = excluded.previous_run_id, root_trigger = excluded.root_trigger, status = excluded.status, error = excluded.error, started = excluded.started, completed = excluded.completed, next_poll = excluded.next_poll;

-- name: WFWorkflowRunDelete :exec
DELETE FROM glue_workflow_run WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id);

-- name: WFWorkflowRunList :many
SELECT * FROM glue_workflow_run WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) ORDER BY started DESC, run_id;

-- name: WFWorkflowRunGet :one
SELECT * FROM glue_workflow_run WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id);

-- name: WFWorkflowRunPropertyPut :exec
INSERT INTO glue_workflow_run_property (partition, account_id, region, name, run_id, item_key, item_value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(run_id), sqlc.arg(item_key), sqlc.arg(item_value))
ON CONFLICT (partition, account_id, region, name, run_id, item_key) DO UPDATE SET item_value = excluded.item_value;

-- name: WFWorkflowRunPropertyDelete :exec
DELETE FROM glue_workflow_run_property WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id);

-- name: WFWorkflowRunPropertyList :many
SELECT * FROM glue_workflow_run_property WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id) ORDER BY partition, account_id, region, name, run_id, item_key;

-- name: WFWorkflowNodePut :exec
INSERT INTO glue_workflow_node (partition, account_id, region, name, run_id, node_id, ordinal, kind, node_name, trigger_name, trigger_type, trigger_state, trigger_description, trigger_schedule, child_run_id, state, error, logical, activated, job_name, crawler_name, security_configuration, timeout, notification_delay) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(run_id), sqlc.arg(node_id), sqlc.arg(ordinal), sqlc.arg(kind), sqlc.arg(node_name), sqlc.arg(trigger_name), sqlc.arg(trigger_type), sqlc.arg(trigger_state), sqlc.arg(trigger_description), sqlc.arg(trigger_schedule), sqlc.arg(child_run_id), sqlc.arg(state), sqlc.arg(error), sqlc.arg(logical), sqlc.arg(activated), sqlc.arg(job_name), sqlc.arg(crawler_name), sqlc.arg(security_configuration), sqlc.arg(timeout), sqlc.arg(notification_delay))
ON CONFLICT (partition, account_id, region, name, run_id, node_id) DO UPDATE SET ordinal = excluded.ordinal, kind = excluded.kind, node_name = excluded.node_name, trigger_name = excluded.trigger_name, trigger_type = excluded.trigger_type, trigger_state = excluded.trigger_state, trigger_description = excluded.trigger_description, trigger_schedule = excluded.trigger_schedule, child_run_id = excluded.child_run_id, state = excluded.state, error = excluded.error, logical = excluded.logical, activated = excluded.activated, job_name = excluded.job_name, crawler_name = excluded.crawler_name, security_configuration = excluded.security_configuration, timeout = excluded.timeout, notification_delay = excluded.notification_delay;

-- name: WFWorkflowNodeDelete :exec
DELETE FROM glue_workflow_node WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id);

-- name: WFWorkflowNodeList :many
SELECT * FROM glue_workflow_node WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id) ORDER BY ordinal;

-- name: WFWorkflowNodeArgumentPut :exec
INSERT INTO glue_workflow_node_argument (partition, account_id, region, name, run_id, node_id, item_key, item_value) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(run_id), sqlc.arg(node_id), sqlc.arg(item_key), sqlc.arg(item_value))
ON CONFLICT (partition, account_id, region, name, run_id, node_id, item_key) DO UPDATE SET item_value = excluded.item_value;

-- name: WFWorkflowNodeArgumentDelete :exec
DELETE FROM glue_workflow_node_argument WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id) AND node_id = sqlc.arg(node_id);

-- name: WFWorkflowNodeArgumentList :many
SELECT * FROM glue_workflow_node_argument WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id) AND node_id = sqlc.arg(node_id) ORDER BY partition, account_id, region, name, run_id, node_id, item_key;

-- name: WFWorkflowNodeConditionPut :exec
INSERT INTO glue_workflow_node_condition (partition, account_id, region, name, run_id, node_id, ordinal, job_name, crawler_name, state, crawl_state, logical_operator) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(name), sqlc.arg(run_id), sqlc.arg(node_id), sqlc.arg(ordinal), sqlc.arg(job_name), sqlc.arg(crawler_name), sqlc.arg(state), sqlc.arg(crawl_state), sqlc.arg(logical_operator))
ON CONFLICT (partition, account_id, region, name, run_id, node_id, ordinal) DO UPDATE SET job_name = excluded.job_name, crawler_name = excluded.crawler_name, state = excluded.state, crawl_state = excluded.crawl_state, logical_operator = excluded.logical_operator;

-- name: WFWorkflowNodeConditionDelete :exec
DELETE FROM glue_workflow_node_condition WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id) AND node_id = sqlc.arg(node_id);

-- name: WFWorkflowNodeConditionList :many
SELECT * FROM glue_workflow_node_condition WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND name = sqlc.arg(name) AND run_id = sqlc.arg(run_id) AND node_id = sqlc.arg(node_id) ORDER BY ordinal;

-- name: WFNextTrigger :one
SELECT * FROM glue_trigger WHERE next_fire IS NOT NULL ORDER BY next_fire, partition, account_id, region, name LIMIT 1;

-- name: WFNextRun :one
SELECT * FROM glue_workflow_run WHERE next_poll IS NOT NULL ORDER BY next_poll, run_id LIMIT 1;
