-- name: GetEventInvokeConfig :one
SELECT * FROM lambda_event_invoke_configs WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: ListEventInvokeConfigs :many
SELECT * FROM lambda_event_invoke_configs WHERE partition=? AND account=? AND region=? AND function_name=? ORDER BY qualifier;
-- name: NextEventInvokeConfigChange :one
SELECT partition,account,region,function_name,qualifier,applies_at,version FROM lambda_event_invoke_configs WHERE applies_at IS NOT NULL
ORDER BY applies_at,'arn:'||partition||':lambda:'||region||':'||account||':function:'||function_name||CASE WHEN qualifier='' THEN '' ELSE ':'||qualifier END LIMIT 1;
-- name: PutEventInvokeConfig :exec
INSERT INTO lambda_event_invoke_configs(partition,account,region,function_name,qualifier,modified,max_age_seconds,max_retries,has_max_age,has_max_retries,effective_max_age_seconds,effective_max_retries,applies_at,version,deleted,on_success_arn,on_failure_arn,effective_on_success_arn,effective_on_failure_arn,owner_stack_id,owner_logical_id,owner_token)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,function_name,qualifier) DO UPDATE SET modified=excluded.modified,max_age_seconds=excluded.max_age_seconds,max_retries=excluded.max_retries,has_max_age=excluded.has_max_age,has_max_retries=excluded.has_max_retries,effective_max_age_seconds=excluded.effective_max_age_seconds,effective_max_retries=excluded.effective_max_retries,applies_at=excluded.applies_at,version=excluded.version,deleted=excluded.deleted,on_success_arn=excluded.on_success_arn,on_failure_arn=excluded.on_failure_arn,effective_on_success_arn=excluded.effective_on_success_arn,effective_on_failure_arn=excluded.effective_on_failure_arn,owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token;
-- name: DeleteEventInvokeConfig :exec
DELETE FROM lambda_event_invoke_configs WHERE partition=? AND account=? AND region=? AND function_name=? AND qualifier=?;
-- name: GetInvocation :one
SELECT * FROM lambda_invocations WHERE id=?;
-- name: NextInvocation :one
SELECT id,version,due FROM lambda_invocations WHERE state='queued' ORDER BY due,id LIMIT 1;
-- name: ListInFlightInvocations :many
SELECT * FROM lambda_invocations WHERE state='in-flight' ORDER BY due,id;
-- name: PutInvocation :exec
INSERT INTO lambda_invocations(id,partition,account,region,function_name,function_arn,payload,request_id,parent_event_id,accepted,due,version,state,invoke_count,system_errors,response_payload,response_error,response_status,response_version,completed,completion,role_arn,max_age_seconds,max_retries,on_success_arn,on_failure_arn,dead_letter_arn,trace_header,settings_detached)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET due=excluded.due,version=excluded.version,state=excluded.state,invoke_count=excluded.invoke_count,system_errors=excluded.system_errors,response_payload=excluded.response_payload,response_error=excluded.response_error,response_status=excluded.response_status,response_version=excluded.response_version,completed=excluded.completed,completion=excluded.completion,role_arn=excluded.role_arn,max_age_seconds=excluded.max_age_seconds,max_retries=excluded.max_retries,on_success_arn=excluded.on_success_arn,on_failure_arn=excluded.on_failure_arn,dead_letter_arn=excluded.dead_letter_arn,settings_detached=excluded.settings_detached;
-- name: DeleteInvocation :exec
DELETE FROM lambda_invocations WHERE id=?;
-- name: DetachFunctionInvocationSettings :exec
UPDATE lambda_invocations SET settings_detached=true
WHERE partition=? AND account=? AND region=? AND function_name=? AND state != 'completed';
-- name: ReattachInvocationSettings :exec
UPDATE lambda_invocations SET settings_detached=false
WHERE partition=? AND account=? AND region=? AND function_name=? AND state != 'completed'
AND function_arn IN (sqlc.arg(function_arn),sqlc.arg(latest_arn));
