-- name: GetPublisher :one
SELECT * FROM sns_publishers WHERE message_id = ? AND protocol = ?;

-- name: PutPublisher :exec
INSERT INTO sns_publishers (message_id, protocol, account_id, region, partition, access_key_id, request_id, parent_event_id, trace_header, principal_arn, principal_id, user_name, session_type, issuer_arn, issuer_id, has_session_policy, federated_provider, source_identity, mfa_present, mfa_authenticated_at, token_issue_time, transport_known, source_ip, secure_transport, user_agent, signature_version, authentication_method, invoked_by, service_name, service_source_arn, service_type)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (message_id, protocol) DO UPDATE SET
    account_id = excluded.account_id,
    region = excluded.region,
    partition = excluded.partition,
    access_key_id = excluded.access_key_id,
    request_id = excluded.request_id,
    parent_event_id = excluded.parent_event_id,
    trace_header = excluded.trace_header,
    principal_arn = excluded.principal_arn,
    principal_id = excluded.principal_id,
    user_name = excluded.user_name,
    session_type = excluded.session_type,
    issuer_arn = excluded.issuer_arn,
    issuer_id = excluded.issuer_id,
    has_session_policy = excluded.has_session_policy,
    federated_provider = excluded.federated_provider,
    source_identity = excluded.source_identity,
    mfa_present = excluded.mfa_present,
    mfa_authenticated_at = excluded.mfa_authenticated_at,
    token_issue_time = excluded.token_issue_time,
    transport_known = excluded.transport_known,
    source_ip = excluded.source_ip,
    secure_transport = excluded.secure_transport,
    user_agent = excluded.user_agent,
    signature_version = excluded.signature_version,
    authentication_method = excluded.authentication_method,
    invoked_by = excluded.invoked_by,
    service_name = excluded.service_name,
    service_source_arn = excluded.service_source_arn,
    service_type = excluded.service_type;

-- name: ListPublisherLists :many
SELECT * FROM sns_publisher_lists WHERE message_id = ? AND protocol = ? ORDER BY kind, position;

-- name: ClearPublisherLists :exec
DELETE FROM sns_publisher_lists WHERE message_id = ? AND protocol = ?;

-- name: InsertPublisherList :exec
INSERT INTO sns_publisher_lists (message_id, protocol, kind, position, value) VALUES (?, ?, ?, ?, ?);

-- name: ListPublisherTags :many
SELECT * FROM sns_publisher_tags WHERE message_id = ? AND protocol = ? ORDER BY tag_key;

-- name: ClearPublisherTags :exec
DELETE FROM sns_publisher_tags WHERE message_id = ? AND protocol = ?;

-- name: InsertPublisherTag :exec
INSERT INTO sns_publisher_tags (message_id, protocol, tag_key, tag_value) VALUES (?, ?, ?, ?);

-- name: ListPublisherContext :many
SELECT * FROM sns_publisher_context WHERE message_id = ? AND protocol = ? ORDER BY context_key, position;

-- name: ClearPublisherContext :exec
DELETE FROM sns_publisher_context WHERE message_id = ? AND protocol = ?;

-- name: InsertPublisherContext :exec
INSERT INTO sns_publisher_context (message_id, protocol, context_key, position, value) VALUES (?, ?, ?, ?, ?);
