-- Command documents own immutable source text independently of Parameter Store.
CREATE TABLE ssm_documents (
    id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    document_uuid TEXT NOT NULL,
    default_version INTEGER NOT NULL,
    latest_version INTEGER NOT NULL,
    next_version INTEGER NOT NULL,
    UNIQUE (partition, account_id, region, name)
);
CREATE TABLE ssm_document_tags (
    document_id INTEGER NOT NULL REFERENCES ssm_documents(id) ON DELETE CASCADE,
    tag_key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (document_id, tag_key)
);
CREATE TABLE ssm_document_versions (
    document_id INTEGER NOT NULL REFERENCES ssm_documents(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    content TEXT NOT NULL,
    format TEXT NOT NULL,
    hash TEXT NOT NULL,
    version_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    target_type TEXT NOT NULL,
    created DATETIME NOT NULL,
    status TEXT NOT NULL,
    ready_at DATETIME NOT NULL,
    PRIMARY KEY (document_id, version)
);
CREATE UNIQUE INDEX ssm_document_version_names ON ssm_document_versions(document_id, version_name) WHERE version_name <> '';
CREATE INDEX ssm_document_activation ON ssm_document_versions(ready_at, document_id, version) WHERE status IN ('Creating', 'Updating');

-- Managed-node observations and Run Command state are separate from documents.
CREATE TABLE ssm_nodes (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    node_id TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    platform_type TEXT NOT NULL,
    platform_name TEXT NOT NULL,
    platform_version TEXT NOT NULL,
    computer_name TEXT NOT NULL,
    registered_at DATETIME NOT NULL,
    last_ping DATETIME NOT NULL,
    PRIMARY KEY (partition, account_id, region, node_id)
);
CREATE TABLE ssm_commands (
    id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    command_id TEXT NOT NULL,
    document_name TEXT NOT NULL,
    document_version TEXT NOT NULL,
    document_hash TEXT NOT NULL,
    content TEXT NOT NULL,
    comment TEXT NOT NULL,
    parameters_present BOOLEAN NOT NULL,
    instance_ids_present BOOLEAN NOT NULL,
    targets_present BOOLEAN NOT NULL,
    requested_at DATETIME NOT NULL,
    delivery_deadline DATETIME NOT NULL,
    empty_target_ready_at TIMESTAMP,
    timeout_seconds INTEGER NOT NULL,
    max_concurrency TEXT NOT NULL,
    max_errors TEXT NOT NULL,
    concurrency INTEGER NOT NULL,
    error_budget INTEGER NOT NULL,
    output_bucket TEXT NOT NULL,
    output_prefix TEXT NOT NULL,
    output_region TEXT NOT NULL,
    log_group TEXT NOT NULL,
    cloud_watch_enabled BOOLEAN NOT NULL,
    status TEXT NOT NULL,
    status_details TEXT NOT NULL,
    parent_event_id TEXT NOT NULL,
    UNIQUE (partition, account_id, region, command_id)
);
CREATE INDEX ssm_commands_deadline ON ssm_commands(delivery_deadline, partition, account_id, region, command_id)
    WHERE status IN ('Pending', 'InProgress', 'Cancelling');
CREATE TABLE ssm_command_parameters (
    command_id INTEGER NOT NULL REFERENCES ssm_commands(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    values_present BOOLEAN NOT NULL,
    PRIMARY KEY (command_id, name)
);
CREATE TABLE ssm_command_parameter_values (
    command_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (command_id, name, position),
    FOREIGN KEY (command_id, name) REFERENCES ssm_command_parameters(command_id, name) ON DELETE CASCADE
);
CREATE TABLE ssm_command_instance_ids (
    command_id INTEGER NOT NULL REFERENCES ssm_commands(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    node_id TEXT NOT NULL,
    PRIMARY KEY (command_id, position)
);
CREATE TABLE ssm_command_targets (
    command_id INTEGER NOT NULL REFERENCES ssm_commands(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    target_key TEXT NOT NULL,
    values_present BOOLEAN NOT NULL,
    PRIMARY KEY (command_id, position)
);
CREATE TABLE ssm_command_target_values (
    command_id INTEGER NOT NULL,
    target_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (command_id, target_position, position),
    FOREIGN KEY (command_id, target_position) REFERENCES ssm_command_targets(command_id, position) ON DELETE CASCADE
);
CREATE TABLE ssm_command_invocations (
    id INTEGER PRIMARY KEY,
    command_id INTEGER NOT NULL REFERENCES ssm_commands(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    instance_name TEXT NOT NULL,
    status TEXT NOT NULL,
    status_details TEXT NOT NULL,
    trace TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    cancel_id TEXT NOT NULL,
    cancel_job_id TEXT NOT NULL,
    delivered_at DATETIME,
    started_at DATETIME,
    finished_at DATETIME,
    retry_at DATETIME,
    delivery_acknowledged BOOLEAN NOT NULL,
    cancel_acknowledged BOOLEAN NOT NULL,
    plugins_present BOOLEAN NOT NULL,
    reply_ids_present BOOLEAN NOT NULL,
    UNIQUE (command_id, node_id)
);
CREATE INDEX ssm_command_invocations_node ON ssm_command_invocations(node_id, command_id);
CREATE TABLE ssm_command_plugins (
    invocation_id INTEGER NOT NULL REFERENCES ssm_command_invocations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    status_details TEXT NOT NULL,
    code INTEGER NOT NULL,
    output TEXT NOT NULL,
    standard_output TEXT NOT NULL,
    standard_error TEXT NOT NULL,
    started_at DATETIME,
    finished_at DATETIME,
    output_bucket TEXT NOT NULL,
    output_prefix TEXT NOT NULL,
    PRIMARY KEY (invocation_id, position)
);
CREATE TABLE ssm_command_reply_ids (
    invocation_id INTEGER NOT NULL REFERENCES ssm_command_invocations(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    reply_id TEXT NOT NULL,
    PRIMARY KEY (invocation_id, position)
);
