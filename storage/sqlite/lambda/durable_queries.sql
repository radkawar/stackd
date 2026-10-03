-- name: GetFunctionDurableConfig :one
SELECT * FROM lambda_function_durable_configs WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: DeleteFunctionDurableConfig :exec
DELETE FROM lambda_function_durable_configs WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: PutFunctionDurableConfig :exec
INSERT INTO lambda_function_durable_configs(partition,account,region,function_name,pending,version,execution_timeout,retention_days,kms_key_arn) VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account,region,function_name,pending,version) DO UPDATE SET execution_timeout=excluded.execution_timeout,retention_days=excluded.retention_days,kms_key_arn=excluded.kms_key_arn;

-- name: GetDurableExecution :one
SELECT * FROM lambda_durable_executions WHERE arn=?;
-- name: ListDurableExecutions :many
SELECT * FROM lambda_durable_executions ORDER BY arn;
-- name: DeleteDurableExecution :exec
DELETE FROM lambda_durable_executions WHERE arn=?;
-- name: PutDurableExecution :execrows
INSERT INTO lambda_durable_executions(arn,name,id,partition,account,region,function_name,function_version,key_arn,wrapped_key,encrypted,status,input,result,started_at,ended_at,deadline,expires_at,execution_timeout,retention_days,token,generation,claimed,next_run_at,invocation_type,trace_id,client_context)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(arn) DO UPDATE SET status=excluded.status,input=excluded.input,result=excluded.result,ended_at=excluded.ended_at,deadline=excluded.deadline,expires_at=excluded.expires_at,execution_timeout=excluded.execution_timeout,retention_days=excluded.retention_days,token=excluded.token,generation=excluded.generation,claimed=excluded.claimed,next_run_at=excluded.next_run_at,invocation_type=excluded.invocation_type,trace_id=excluded.trace_id,client_context=excluded.client_context
WHERE lambda_durable_executions.name=excluded.name AND lambda_durable_executions.id=excluded.id
AND lambda_durable_executions.partition=excluded.partition AND lambda_durable_executions.account=excluded.account AND lambda_durable_executions.region=excluded.region
AND lambda_durable_executions.function_name=excluded.function_name AND lambda_durable_executions.function_version=excluded.function_version AND lambda_durable_executions.started_at=excluded.started_at
AND lambda_durable_executions.key_arn=excluded.key_arn AND COALESCE(lambda_durable_executions.wrapped_key,X'')=COALESCE(excluded.wrapped_key,X'') AND lambda_durable_executions.encrypted=excluded.encrypted;

-- name: ListDurableHistory :many
SELECT * FROM lambda_durable_history WHERE execution_arn=? ORDER BY position;
-- name: DeleteDurableHistory :exec
DELETE FROM lambda_durable_history WHERE execution_arn=?;
-- name: PutDurableHistory :exec
INSERT INTO lambda_durable_history(execution_arn,position,id,at,type) VALUES(?,?,?,?,?);

-- name: ListDurableCheckpoints :many
SELECT * FROM lambda_durable_checkpoints WHERE execution_arn=? ORDER BY position;
-- name: DeleteDurableCheckpoints :exec
DELETE FROM lambda_durable_checkpoints WHERE execution_arn=?;
-- name: PutDurableCheckpoint :exec
INSERT INTO lambda_durable_checkpoints(execution_arn,position,client_token,previous_token,next_token,request,expires_at) VALUES(?,?,?,?,?,?,?);

-- name: ListDurableOperations :many
SELECT * FROM lambda_durable_operations WHERE execution_arn=? AND collection=? AND snapshot_position=? ORDER BY position;
-- name: DeleteDurableOperations :exec
DELETE FROM lambda_durable_operations WHERE execution_arn=?;
-- name: PutDurableOperation :exec
INSERT INTO lambda_durable_operations(execution_arn,collection,snapshot_position,position,id,parent_id,name,type,sub_type,status,started_at,ended_at,due_at,payload,attempt,replay_children,callback_id,callback_timeout_at,heartbeat_at,heartbeat_seconds,timeout_seconds,target_function,target_tenant,generation)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);

-- name: GetDurableError :one
SELECT * FROM lambda_durable_errors WHERE execution_arn=? AND collection=? AND snapshot_position=? AND position=?;
-- name: DeleteDurableErrors :exec
DELETE FROM lambda_durable_errors WHERE execution_arn=?;
-- name: PutDurableError :exec
INSERT INTO lambda_durable_errors(execution_arn,collection,snapshot_position,position,error_data,error_message,error_type,has_stack_trace) VALUES(?,?,?,?,?,?,?,?);
-- name: ListDurableErrorFrames :many
SELECT frame FROM lambda_durable_error_frames WHERE execution_arn=? AND collection=? AND snapshot_position=? AND operation_position=? ORDER BY position;
-- name: PutDurableErrorFrame :exec
INSERT INTO lambda_durable_error_frames(execution_arn,collection,snapshot_position,operation_position,position,frame) VALUES(?,?,?,?,?,?);
