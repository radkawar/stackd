-- name: ListTags :many
SELECT key, value FROM config_tags WHERE partition=? AND account_id=? AND region=? AND arn=? ORDER BY key;

-- name: ClearTags :exec
DELETE FROM config_tags WHERE partition=? AND account_id=? AND region=? AND arn=?;

-- name: InsertTag :exec
INSERT INTO config_tags (partition, account_id, region, arn, key, value) VALUES (?, ?, ?, ?, ?, ?);

-- name: PutRecorder :one
INSERT INTO config_recorders (partition, account_id, region, name, arn, role_arn, all_supported, include_global, recording, last_start, last_stop, last_status_change, last_status, last_error_code, last_error_message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region) DO UPDATE SET name=excluded.name, arn=excluded.arn, role_arn=excluded.role_arn, all_supported=excluded.all_supported, include_global=excluded.include_global, recording=excluded.recording, last_start=excluded.last_start, last_stop=excluded.last_stop, last_status_change=excluded.last_status_change, last_status=excluded.last_status, last_error_code=excluded.last_error_code, last_error_message=excluded.last_error_message
RETURNING row_id;

-- name: GetRecorder :one
SELECT * FROM config_recorders WHERE partition=? AND account_id=? AND region=?;

-- name: DeleteRecorder :exec
DELETE FROM config_recorders WHERE partition=? AND account_id=? AND region=?;

-- name: PutChannel :exec
INSERT INTO config_channels (partition, account_id, region, name, bucket, prefix, kms_key_arn, topic_arn, frequency, last_attempt, last_success, next_delivery, status, error_code, error_message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region) DO UPDATE SET name=excluded.name, bucket=excluded.bucket, prefix=excluded.prefix, kms_key_arn=excluded.kms_key_arn, topic_arn=excluded.topic_arn, frequency=excluded.frequency, last_attempt=excluded.last_attempt, last_success=excluded.last_success, next_delivery=excluded.next_delivery, status=excluded.status, error_code=excluded.error_code, error_message=excluded.error_message;

-- name: GetChannel :one
SELECT * FROM config_channels WHERE partition=? AND account_id=? AND region=?;

-- name: DeleteChannel :exec
DELETE FROM config_channels WHERE partition=? AND account_id=? AND region=?;

-- name: AppendItem :one
INSERT INTO config_items (partition, account_id, region, resource_type, resource_id, resource_name, arn, availability_zone, capture_time, creation_time, status, configuration)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING sequence;

-- name: ListItems :many
SELECT * FROM config_items WHERE partition=? AND account_id=? AND region=? ORDER BY sequence;

-- name: PutDelivery :exec
INSERT INTO config_deliveries (partition, account_id, region, id, channel_name, kind, object_key, due, created_at, completed_at, status, error_code, error_message, attempts, first_sequence, last_sequence)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, id) DO UPDATE SET channel_name=excluded.channel_name, kind=excluded.kind, object_key=excluded.object_key, due=excluded.due, created_at=excluded.created_at, completed_at=excluded.completed_at, status=excluded.status, error_code=excluded.error_code, error_message=excluded.error_message, attempts=excluded.attempts, first_sequence=excluded.first_sequence, last_sequence=excluded.last_sequence;

-- name: ListDeliveries :many
SELECT * FROM config_deliveries ORDER BY due, partition, account_id, region, id;

-- name: PutRule :one
INSERT INTO config_rules (partition, account_id, region, name, id, arn, description, owner, source_identifier, parameters_present, resource_id, tag_key, tag_value, created_at, last_evaluation, last_reevaluation, error_code, error_message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET id=excluded.id, arn=excluded.arn, description=excluded.description, owner=excluded.owner, source_identifier=excluded.source_identifier, parameters_present=excluded.parameters_present, resource_id=excluded.resource_id, tag_key=excluded.tag_key, tag_value=excluded.tag_value, created_at=excluded.created_at, last_evaluation=excluded.last_evaluation, last_reevaluation=excluded.last_reevaluation, error_code=excluded.error_code, error_message=excluded.error_message
RETURNING row_id;

-- name: ListRules :many
SELECT * FROM config_rules WHERE partition=? AND account_id=? AND region=? ORDER BY name;

-- name: DeleteRule :exec
DELETE FROM config_rules WHERE partition=? AND account_id=? AND region=? AND name=?;

-- name: PutEvaluation :exec
INSERT INTO config_evaluations (partition, account_id, region, rule_name, resource_type, resource_id, compliance_type, annotation, ordering_time, recorded_at, invoked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, rule_name, resource_type, resource_id) DO UPDATE SET compliance_type=excluded.compliance_type, annotation=excluded.annotation, ordering_time=excluded.ordering_time, recorded_at=excluded.recorded_at, invoked_at=excluded.invoked_at;

-- name: ListEvaluations :many
SELECT * FROM config_evaluations WHERE partition=? AND account_id=? AND region=? ORDER BY rule_name, resource_type, resource_id;

-- name: PutEvaluationRun :exec
INSERT INTO config_evaluation_runs (partition, account_id, region, token, rule_name, item_sequence, due, created_at, completed_at, status, error_code, error_message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, token) DO UPDATE SET rule_name=excluded.rule_name, item_sequence=excluded.item_sequence, due=excluded.due, created_at=excluded.created_at, completed_at=excluded.completed_at, status=excluded.status, error_code=excluded.error_code, error_message=excluded.error_message;

-- name: ListEvaluationRuns :many
SELECT * FROM config_evaluation_runs ORDER BY due, partition, account_id, region, token;

-- name: PutAggregator :one
INSERT INTO config_aggregators (partition, account_id, region, name, arn, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, name) DO UPDATE SET arn=excluded.arn, created_at=excluded.created_at, updated_at=excluded.updated_at
RETURNING row_id;

-- name: ListAggregators :many
SELECT * FROM config_aggregators WHERE partition=? AND account_id=? AND region=? ORDER BY name;

-- name: DeleteAggregator :exec
DELETE FROM config_aggregators WHERE partition=? AND account_id=? AND region=? AND name=?;

-- name: PutAggregationAuthorization :exec
INSERT INTO config_aggregation_authorizations (partition, account_id, region, authorized_account_id, authorized_region, arn, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, authorized_account_id, authorized_region) DO UPDATE SET arn=excluded.arn, created_at=excluded.created_at;

-- name: ListAggregationAuthorizations :many
SELECT * FROM config_aggregation_authorizations WHERE partition=? AND account_id=? AND region=? ORDER BY authorized_account_id, authorized_region;

-- name: DeleteAggregationAuthorization :exec
DELETE FROM config_aggregation_authorizations WHERE partition=? AND account_id=? AND region=? AND authorized_account_id=? AND authorized_region=?;

-- name: InsertRecorderType :exec
INSERT INTO config_recorder_types (parent_id, kind, ordinal, resource_type) VALUES (?, ?, ?, ?);

-- name: ListRecorderTypes :many
SELECT * FROM config_recorder_types WHERE parent_id=? ORDER BY kind, ordinal;

-- name: ClearRecorderTypes :exec
DELETE FROM config_recorder_types WHERE parent_id=?;

-- name: InsertItemTag :exec
INSERT INTO config_item_tags (parent_id, tag_key, value) VALUES (?, ?, ?);

-- name: ListItemTags :many
SELECT * FROM config_item_tags WHERE parent_id=? ORDER BY tag_key;

-- name: InsertItemSupplement :exec
INSERT INTO config_item_supplementary (parent_id, name, document) VALUES (?, ?, ?);

-- name: ListItemSupplements :many
SELECT * FROM config_item_supplementary WHERE parent_id=? ORDER BY name;

-- name: InsertItemRelationship :exec
INSERT INTO config_item_relationships (parent_id, ordinal, resource_type, resource_id, resource_name, name) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListItemRelationships :many
SELECT * FROM config_item_relationships WHERE parent_id=? ORDER BY ordinal;

-- name: InsertRuleType :exec
INSERT INTO config_rule_types (parent_id, ordinal, resource_type) VALUES (?, ?, ?);

-- name: ListRuleTypes :many
SELECT * FROM config_rule_types WHERE parent_id=? ORDER BY ordinal;

-- name: ClearRuleTypes :exec
DELETE FROM config_rule_types WHERE parent_id=?;

-- name: InsertRuleMessage :exec
INSERT INTO config_rule_messages (parent_id, ordinal, message) VALUES (?, ?, ?);

-- name: ListRuleMessages :many
SELECT * FROM config_rule_messages WHERE parent_id=? ORDER BY ordinal;

-- name: ClearRuleMessages :exec
DELETE FROM config_rule_messages WHERE parent_id=?;

-- name: InsertRuleParameter :exec
INSERT INTO config_rule_parameters (parent_id, parameter_key, value) VALUES (?, ?, ?);

-- name: ListRuleParameters :many
SELECT * FROM config_rule_parameters WHERE parent_id=? ORDER BY parameter_key;

-- name: ClearRuleParameters :exec
DELETE FROM config_rule_parameters WHERE parent_id=?;

-- name: InsertAggregatorSource :exec
INSERT INTO config_aggregator_sources (parent_id, ordinal, source_account_id, source_region) VALUES (?, ?, ?, ?);

-- name: ListAggregatorSources :many
SELECT * FROM config_aggregator_sources WHERE parent_id=? ORDER BY ordinal;

-- name: ClearAggregatorSources :exec
DELETE FROM config_aggregator_sources WHERE parent_id=?;

-- name: DeleteEvaluations :exec
DELETE FROM config_evaluations WHERE partition=? AND account_id=? AND region=? AND rule_name=?;

-- name: DeleteEvaluationRuns :exec
DELETE FROM config_evaluation_runs WHERE partition=? AND account_id=? AND region=? AND rule_name=?;
