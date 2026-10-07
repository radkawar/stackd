-- name: GetDatabase :one
SELECT * FROM rds_database WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: ListDatabases :many
SELECT * FROM rds_database WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) ORDER BY kind,name;

-- name: PutDatabase :exec
INSERT INTO rds_database (partition,account_id,region,kind,name,engine,engine_version,database_name,username,class,parameter_group,cluster,runtime_id,status,desired,operation,restore_snapshot,ciphertext,pending_ciphertext,address,port,requested_port,version,created,due,deletion_protection,http_enabled,copy_tags,pending_parameters,resource_id,owner_stack_id,owner_logical_id,owner_token) VALUES (sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(kind),sqlc.arg(name),sqlc.arg(engine),sqlc.arg(engine_version),sqlc.arg(database_name),sqlc.arg(username),sqlc.arg(class),sqlc.arg(parameter_group),sqlc.arg(cluster),sqlc.arg(runtime_id),sqlc.arg(status),sqlc.arg(desired),sqlc.arg(operation),sqlc.arg(restore_snapshot),sqlc.arg(ciphertext),sqlc.arg(pending_ciphertext),sqlc.arg(address),sqlc.arg(port),sqlc.arg(requested_port),sqlc.arg(version),sqlc.arg(created),sqlc.arg(due),sqlc.arg(deletion_protection),sqlc.arg(http_enabled),sqlc.arg(copy_tags),sqlc.arg(pending_parameters),sqlc.arg(resource_id),sqlc.arg(owner_stack_id),sqlc.arg(owner_logical_id),sqlc.arg(owner_token)) ON CONFLICT (partition,account_id,region,kind,name) DO UPDATE SET engine=excluded.engine,engine_version=excluded.engine_version,database_name=excluded.database_name,username=excluded.username,class=excluded.class,parameter_group=excluded.parameter_group,cluster=excluded.cluster,runtime_id=excluded.runtime_id,status=excluded.status,desired=excluded.desired,operation=excluded.operation,restore_snapshot=excluded.restore_snapshot,ciphertext=excluded.ciphertext,pending_ciphertext=excluded.pending_ciphertext,address=excluded.address,port=excluded.port,requested_port=excluded.requested_port,version=excluded.version,created=excluded.created,due=excluded.due,deletion_protection=excluded.deletion_protection,http_enabled=excluded.http_enabled,copy_tags=excluded.copy_tags,pending_parameters=excluded.pending_parameters,resource_id=excluded.resource_id,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;

-- name: DeleteDatabase :exec
DELETE FROM rds_database WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: AllDatabases :many
SELECT * FROM rds_database ORDER BY partition,account_id,region,kind,name;

-- name: GetSnapshot :one
SELECT * FROM rds_snapshot WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: ListSnapshots :many
SELECT * FROM rds_snapshot WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) ORDER BY kind,name;

-- name: PutSnapshot :exec
INSERT INTO rds_snapshot (partition,account_id,region,kind,name,source,source_runtime_id,runtime_id,engine,engine_version,database_name,username,class,status,ciphertext,version,created,due,owner_stack_id,owner_logical_id,owner_token) VALUES (sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(kind),sqlc.arg(name),sqlc.arg(source),sqlc.arg(source_runtime_id),sqlc.arg(runtime_id),sqlc.arg(engine),sqlc.arg(engine_version),sqlc.arg(database_name),sqlc.arg(username),sqlc.arg(class),sqlc.arg(status),sqlc.arg(ciphertext),sqlc.arg(version),sqlc.arg(created),sqlc.arg(due),sqlc.arg(owner_stack_id),sqlc.arg(owner_logical_id),sqlc.arg(owner_token)) ON CONFLICT (partition,account_id,region,kind,name) DO UPDATE SET source=excluded.source,source_runtime_id=excluded.source_runtime_id,runtime_id=excluded.runtime_id,engine=excluded.engine,engine_version=excluded.engine_version,database_name=excluded.database_name,username=excluded.username,class=excluded.class,status=excluded.status,ciphertext=excluded.ciphertext,version=excluded.version,created=excluded.created,due=excluded.due,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;

-- name: DeleteSnapshot :exec
DELETE FROM rds_snapshot WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: AllSnapshots :many
SELECT * FROM rds_snapshot ORDER BY partition,account_id,region,kind,name;

-- name: GetParameterGroup :one
SELECT * FROM rds_parameter_group WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: ListParameterGroups :many
SELECT * FROM rds_parameter_group WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) ORDER BY kind,name;

-- name: PutParameterGroup :exec
INSERT INTO rds_parameter_group (partition,account_id,region,kind,name,family,description,resource_id,owner_stack_id,owner_logical_id,owner_token) VALUES (sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(kind),sqlc.arg(name),sqlc.arg(family),sqlc.arg(description),sqlc.arg(resource_id),sqlc.arg(owner_stack_id),sqlc.arg(owner_logical_id),sqlc.arg(owner_token)) ON CONFLICT (partition,account_id,region,kind,name) DO UPDATE SET family=excluded.family,description=excluded.description,resource_id=excluded.resource_id,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;

-- name: DeleteParameterGroup :exec
DELETE FROM rds_parameter_group WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: GetSubnetGroup :one
SELECT * FROM rds_subnet_group WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: ListSubnetGroups :many
SELECT * FROM rds_subnet_group WHERE partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region) ORDER BY kind,name;

-- name: PutSubnetGroup :exec
INSERT INTO rds_subnet_group (partition,account_id,region,kind,name,description,vpc_id,resource_id,owner_stack_id,owner_logical_id,owner_token) VALUES (sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(kind),sqlc.arg(name),sqlc.arg(description),sqlc.arg(vpc_id),sqlc.arg(resource_id),sqlc.arg(owner_stack_id),sqlc.arg(owner_logical_id),sqlc.arg(owner_token)) ON CONFLICT (partition,account_id,region,kind,name) DO UPDATE SET description=excluded.description,vpc_id=excluded.vpc_id,resource_id=excluded.resource_id,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;

-- name: DeleteSubnetGroup :exec
DELETE FROM rds_subnet_group WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: ListTags :many
SELECT * FROM rds_tag WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name) ORDER BY tag_key;

-- name: PutTag :exec
INSERT INTO rds_tag (partition,account_id,region,kind,name,tag_key,tag_value) VALUES (sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(kind),sqlc.arg(name),sqlc.arg(tag_key),sqlc.arg(tag_value));

-- name: DeleteTags :exec
DELETE FROM rds_tag WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: ListParameters :many
SELECT * FROM rds_parameter WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name) ORDER BY parameter_name;

-- name: PutParameter :exec
INSERT INTO rds_parameter (partition,account_id,region,kind,name,parameter_name,parameter_value,apply_method) VALUES (sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(kind),sqlc.arg(name),sqlc.arg(parameter_name),sqlc.arg(parameter_value),sqlc.arg(apply_method));

-- name: DeleteParameters :exec
DELETE FROM rds_parameter WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

-- name: ListSubnets :many
SELECT * FROM rds_subnet WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name) ORDER BY subnet_id;

-- name: PutSubnet :exec
INSERT INTO rds_subnet (partition,account_id,region,kind,name,subnet_id,vpc_id,availability_zone) VALUES (sqlc.arg(partition),sqlc.arg(account_id),sqlc.arg(region),sqlc.arg(kind),sqlc.arg(name),sqlc.arg(subnet_id),sqlc.arg(vpc_id),sqlc.arg(availability_zone));

-- name: DeleteSubnets :exec
DELETE FROM rds_subnet WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND kind = sqlc.arg(kind) AND name = sqlc.arg(name);

