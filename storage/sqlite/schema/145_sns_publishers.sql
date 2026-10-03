CREATE TABLE sns_publishers (
    message_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    partition TEXT NOT NULL,
    access_key_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    parent_event_id TEXT NOT NULL,
    trace_header TEXT NOT NULL,
    principal_arn TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    session_type TEXT NOT NULL,
    issuer_arn TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    has_session_policy BOOLEAN NOT NULL,
    federated_provider TEXT NOT NULL,
    source_identity TEXT NOT NULL,
    mfa_present BOOLEAN NOT NULL,
    mfa_authenticated_at DATETIME NOT NULL,
    token_issue_time DATETIME NOT NULL,
    transport_known BOOLEAN NOT NULL,
    source_ip TEXT NOT NULL,
    secure_transport BOOLEAN NOT NULL,
    user_agent TEXT NOT NULL,
    signature_version TEXT NOT NULL,
    authentication_method TEXT NOT NULL,
    invoked_by TEXT NOT NULL,
    service_name TEXT NOT NULL,
    service_source_arn TEXT NOT NULL,
    service_type TEXT NOT NULL,
    PRIMARY KEY (message_id, protocol),
    FOREIGN KEY (message_id, protocol) REFERENCES sns_messages(id, protocol) ON DELETE CASCADE
);

CREATE TABLE sns_publisher_lists (
    message_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    kind TEXT NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (message_id, protocol, kind, position),
    FOREIGN KEY (message_id, protocol) REFERENCES sns_publishers(message_id, protocol) ON DELETE CASCADE
);

CREATE TABLE sns_publisher_tags (
    message_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (message_id, protocol, tag_key),
    FOREIGN KEY (message_id, protocol) REFERENCES sns_publishers(message_id, protocol) ON DELETE CASCADE
);

CREATE TABLE sns_publisher_context (
    message_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    context_key TEXT NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (message_id, protocol, context_key, position),
    FOREIGN KEY (message_id, protocol) REFERENCES sns_publishers(message_id, protocol) ON DELETE CASCADE
);
