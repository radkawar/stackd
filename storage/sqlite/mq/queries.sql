-- name: GetBroker :one
SELECT * FROM mq_brokers WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: AllBrokers :many
SELECT * FROM mq_brokers ORDER BY arn;

-- name: PutBroker :exec
INSERT INTO mq_brokers(partition,account_id,region,id,arn,name,engine,engine_version,instance_type,state,creator_request_id,username,password,operation,failure,version,created,due,endpoint_address,endpoint_console_url,endpoint_native_id,endpoint_ca_pem,maintenance_day,maintenance_time,maintenance_zone,maintenance_due,maintenance_adjustments,log_general,log_audit,log_pending_general,log_pending_audit,log_general_file_id,log_general_offset,log_audit_file_id,log_audit_offset,log_delivery_error,log_due)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,id) DO UPDATE SET arn=excluded.arn,name=excluded.name,engine=excluded.engine,engine_version=excluded.engine_version,instance_type=excluded.instance_type,state=excluded.state,creator_request_id=excluded.creator_request_id,username=excluded.username,password=excluded.password,operation=excluded.operation,failure=excluded.failure,version=excluded.version,created=excluded.created,due=excluded.due,endpoint_address=excluded.endpoint_address,endpoint_console_url=excluded.endpoint_console_url,endpoint_native_id=excluded.endpoint_native_id,endpoint_ca_pem=excluded.endpoint_ca_pem,maintenance_day=excluded.maintenance_day,maintenance_time=excluded.maintenance_time,maintenance_zone=excluded.maintenance_zone,maintenance_due=excluded.maintenance_due,maintenance_adjustments=excluded.maintenance_adjustments,log_general=excluded.log_general,log_audit=excluded.log_audit,log_pending_general=excluded.log_pending_general,log_pending_audit=excluded.log_pending_audit,log_general_file_id=excluded.log_general_file_id,log_general_offset=excluded.log_general_offset,log_audit_file_id=excluded.log_audit_file_id,log_audit_offset=excluded.log_audit_offset,log_delivery_error=excluded.log_delivery_error,log_due=excluded.log_due;

-- name: DeleteBroker :exec
DELETE FROM mq_brokers WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: ListBrokerTags :many
SELECT tag_key,tag_value FROM mq_broker_tags WHERE arn=? ORDER BY tag_key;

-- name: DeleteBrokerTags :exec
DELETE FROM mq_broker_tags WHERE arn=?;

-- name: PutBrokerTag :exec
INSERT INTO mq_broker_tags(arn,tag_key,tag_value) VALUES(?,?,?);

-- name: ListBrokerUsers :many
SELECT * FROM mq_broker_users WHERE arn=? ORDER BY username;

-- name: DeleteBrokerUsers :exec
DELETE FROM mq_broker_users WHERE arn=?;

-- name: PutBrokerUser :exec
INSERT INTO mq_broker_users(arn,username,password,console_access,pending_change,pending_password,pending_console_access) VALUES(?,?,?,?,?,?,?);

-- name: ListBrokerUserGroups :many
SELECT * FROM mq_broker_user_groups WHERE arn=? ORDER BY username,pending,group_name;

-- name: PutBrokerUserGroup :exec
INSERT INTO mq_broker_user_groups(arn,username,pending,group_name) VALUES(?,?,?,?);

-- name: ListBrokerConfigurations :many
SELECT * FROM mq_broker_configurations WHERE arn=? ORDER BY kind,position;

-- name: DeleteBrokerConfigurations :exec
DELETE FROM mq_broker_configurations WHERE arn=?;

-- name: PutBrokerConfiguration :exec
INSERT INTO mq_broker_configurations(arn,kind,position,configuration_id,revision,data) VALUES(?,?,?,?,?,?);

-- name: GetConfiguration :one
SELECT * FROM mq_configurations WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: AllConfigurations :many
SELECT * FROM mq_configurations ORDER BY arn;

-- name: PutConfiguration :exec
INSERT INTO mq_configurations(partition,account_id,region,id,arn,name,description,engine,engine_version,authentication_strategy,created)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,id) DO UPDATE SET arn=excluded.arn,name=excluded.name,description=excluded.description,engine=excluded.engine,engine_version=excluded.engine_version,authentication_strategy=excluded.authentication_strategy,created=excluded.created;

-- name: DeleteConfiguration :exec
DELETE FROM mq_configurations WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: ListConfigurationTags :many
SELECT tag_key,tag_value FROM mq_configuration_tags WHERE arn=? ORDER BY tag_key;

-- name: DeleteConfigurationTags :exec
DELETE FROM mq_configuration_tags WHERE arn=?;

-- name: PutConfigurationTag :exec
INSERT INTO mq_configuration_tags(arn,tag_key,tag_value) VALUES(?,?,?);

-- name: ListConfigurationRevisions :many
SELECT * FROM mq_configuration_revisions WHERE arn=? ORDER BY revision;

-- name: DeleteConfigurationRevisions :exec
DELETE FROM mq_configuration_revisions WHERE arn=?;

-- name: PutConfigurationRevision :exec
INSERT INTO mq_configuration_revisions(arn,revision,description,data,created) VALUES(?,?,?,?,?);
