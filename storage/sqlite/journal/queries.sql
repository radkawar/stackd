-- name: AppendEnvelope :one
INSERT INTO kernel_events (occurred_at, partition, account_id, region, request_id, actor_arn, event_type, parent_event_id, actor_service)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING sequence;

-- name: AppendSessionIssued :exec
INSERT INTO iam_session_events (sequence, principal_arn, issuer_arn, session_type, expiration)
VALUES (?, ?, ?, ?, ?);

-- name: AppendAccessKeyChanged :exec
INSERT INTO iam_access_key_events (sequence, change_kind, access_key_id, principal_arn, key_status)
VALUES (?, ?, ?, ?, ?);

-- name: AppendAccountCreationChanged :exec
INSERT INTO org_account_creation_events (sequence, organization_id, creation_request_id, account_id, state, failure_reason)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ReadEvents :many
SELECT e.sequence, e.occurred_at, e.partition, e.account_id, e.region, e.request_id, e.actor_arn, e.parent_event_id, e.actor_service,
       e.event_type, s.principal_arn, s.issuer_arn, s.session_type, s.expiration,
       k.change_kind, k.access_key_id, k.principal_arn AS key_principal_arn, k.key_status,
       c.organization_id, c.creation_request_id, c.account_id AS created_account_id, c.state AS creation_state, c.failure_reason,
       i.organization_id AS handshake_organization_id, i.handshake_id, i.target_account_id, i.state AS handshake_state, i.action AS handshake_action, i.parent_id AS parent_handshake_id,
       p.organization_id AS policy_organization_id, p.target_account_id AS policy_account_id, p.policy_type, p.state AS policy_state
FROM kernel_events e LEFT JOIN iam_session_events s USING (sequence)
LEFT JOIN iam_access_key_events k USING (sequence)
LEFT JOIN org_account_creation_events c USING (sequence)
LEFT JOIN org_handshake_events i USING (sequence)
LEFT JOIN org_effective_policy_events p USING (sequence)
WHERE e.sequence > ? ORDER BY e.sequence LIMIT ?;

-- name: AppendHandshakeChanged :exec
INSERT INTO org_handshake_events (sequence, organization_id, handshake_id, target_account_id, state, action, parent_id) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: AppendEffectivePolicyChanged :exec
INSERT INTO org_effective_policy_events (sequence, organization_id, target_account_id, policy_type, state) VALUES (?, ?, ?, ?, ?);

-- name: AppendAPICall :exec
INSERT INTO api_call_events (sequence,event_id,event_source,event_name,event_category,read_only,identity_type,principal_id,identity_account_id,access_key_id,user_name,issuer_id,issuer_arn,issuer_user_name,session_created_at,mfa_authenticated,source_identity,source_ip_address,user_agent,error_code,error_message,request_parameters,response_elements,additional_event_data,identity_provider,shared_event_id,api_version,service_event,service_event_details,issuer_type,credentials_issued_to,ec2_role_delivery,cloudtrail_event_type)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);

-- name: AppendAPICallResource :exec
INSERT INTO api_call_event_resources (sequence,position,resource_type,resource_name) VALUES (?,?,?,?);

-- name: ReadAPICall :one
SELECT * FROM api_call_events WHERE sequence=?;

-- name: ReadAPICallResources :many
SELECT resource_type,resource_name FROM api_call_event_resources WHERE sequence=? ORDER BY position;

-- name: LastSequence :one
SELECT CAST(COALESCE(MAX(sequence),0) AS INTEGER) FROM kernel_events;

-- name: LookupAPICalls :many
SELECT e.sequence,e.occurred_at,e.partition,e.account_id,e.region,e.request_id,e.actor_arn,e.parent_event_id,e.actor_service
FROM kernel_events e JOIN api_call_events a USING(sequence)
WHERE e.partition=sqlc.arg(partition) AND e.account_id=sqlc.arg(account_id) AND e.region=sqlc.arg(region)
AND a.event_category='Management'
AND e.occurred_at>=sqlc.arg(start_time) AND e.occurred_at<=sqlc.arg(end_time)
AND e.sequence<=sqlc.arg(max_sequence)
AND (sqlc.arg(before_sequence)=0 OR e.occurred_at<sqlc.arg(before_time) OR (e.occurred_at=sqlc.arg(before_time) AND e.sequence<sqlc.arg(before_sequence)))
AND (sqlc.arg(attribute_key)=''
 OR (sqlc.arg(attribute_key)='EventId' AND a.event_id=sqlc.arg(attribute_value))
 OR (sqlc.arg(attribute_key)='EventName' AND a.event_name=sqlc.arg(attribute_value))
 OR (sqlc.arg(attribute_key)='EventSource' AND a.event_source=sqlc.arg(attribute_value))
 OR (sqlc.arg(attribute_key)='AccessKeyId' AND a.access_key_id=sqlc.arg(attribute_value))
 OR (sqlc.arg(attribute_key)='Username' AND a.user_name=sqlc.arg(attribute_value))
 OR (sqlc.arg(attribute_key)='ReadOnly' AND ((a.read_only=1 AND sqlc.arg(attribute_value)='true') OR (a.read_only=0 AND sqlc.arg(attribute_value)='false')))
 OR (sqlc.arg(attribute_key)='ResourceType' AND EXISTS(SELECT 1 FROM api_call_event_resources r WHERE r.sequence=e.sequence AND r.resource_type=sqlc.arg(attribute_value)))
 OR (sqlc.arg(attribute_key)='ResourceName' AND EXISTS(SELECT 1 FROM api_call_event_resources r WHERE r.sequence=e.sequence AND r.resource_name=sqlc.arg(attribute_value))))
ORDER BY e.occurred_at DESC,e.sequence DESC LIMIT sqlc.arg(page_limit);

-- name: AppendEventBridgeAccepted :exec
INSERT INTO eventbridge_accepted_events (sequence,event_id,event_bus_arn,wire_event_id) VALUES (?,?,?,?);

-- name: ReadEventBridgeAccepted :one
SELECT event_id,event_bus_arn,wire_event_id FROM eventbridge_accepted_events WHERE sequence=?;

-- name: AppendSQSMessageAccepted :exec
INSERT INTO sqs_message_accepted_events (sequence,message_id,queue_arn) VALUES (?,?,?);

-- name: ReadSQSMessageAccepted :one
SELECT message_id,queue_arn FROM sqs_message_accepted_events WHERE sequence=?;

-- name: AppendLambdaInvocationAccepted :exec
INSERT INTO lambda_invocation_accepted_events (sequence,invocation_id,function_arn) VALUES (?,?,?);

-- name: ReadLambdaInvocationAccepted :one
SELECT invocation_id,function_arn FROM lambda_invocation_accepted_events WHERE sequence=?;

-- name: AppendLambdaSourceBatchAccepted :exec
INSERT INTO lambda_source_batch_events(sequence,invocation_event_id,mapping_arn,source_arn) VALUES (?,?,?,?);

-- name: AppendLambdaSourceBatchRecord :exec
INSERT INTO lambda_source_batch_records(sequence,ordinal,record_id) VALUES (?,?,?);

-- name: ReadLambdaSourceBatchAccepted :one
SELECT invocation_event_id,mapping_arn,source_arn FROM lambda_source_batch_events WHERE sequence=?;

-- name: ReadLambdaSourceBatchRecords :many
SELECT record_id FROM lambda_source_batch_records WHERE sequence=? ORDER BY ordinal;

-- name: AppendLogsBatchAccepted :exec
INSERT INTO logs_batch_accepted_events (sequence,batch_id,log_group_arn,log_stream_name,event_count) VALUES (?,?,?,?,?);

-- name: ReadLogsBatchAccepted :one
SELECT batch_id,log_group_arn,log_stream_name,event_count FROM logs_batch_accepted_events WHERE sequence=?;

-- name: AppendAPICallNativeResource :exec
INSERT INTO api_call_native_resources(sequence,position,account_id,resource_type,arn,arn_prefix) VALUES (?,?,?,?,?,?);

-- name: ReadAPICallNativeResources :many
SELECT account_id,resource_type,arn,arn_prefix FROM api_call_native_resources WHERE sequence=? ORDER BY position;

-- name: ReadAPICallEnvelopes :many
SELECT e.sequence,e.occurred_at,e.partition,e.account_id,e.region,e.request_id,e.actor_arn,e.parent_event_id,e.actor_service
FROM kernel_events e JOIN api_call_events a USING(sequence)
WHERE a.event_id IN (sqlc.slice('event_ids')) ORDER BY e.sequence;
