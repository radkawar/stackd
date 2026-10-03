-- AWS Config controls are normalized; only immutable configuration observations
-- and supplementary observations retain native customer document text.

CREATE TABLE config_recorders (
    row_id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    arn TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    all_supported BOOLEAN NOT NULL,
    include_global BOOLEAN NOT NULL,
    recording BOOLEAN NOT NULL,
    last_start DATETIME NOT NULL,
    last_stop DATETIME NOT NULL,
    last_status_change DATETIME NOT NULL,
    last_status TEXT NOT NULL,
    last_error_code TEXT NOT NULL,
    last_error_message TEXT NOT NULL,
    UNIQUE (partition, account_id, region)
);

CREATE TABLE config_channels (
    row_id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    bucket TEXT NOT NULL,
    prefix TEXT NOT NULL,
    kms_key_arn TEXT NOT NULL,
    topic_arn TEXT NOT NULL,
    frequency TEXT NOT NULL,
    last_attempt DATETIME NOT NULL,
    last_success DATETIME NOT NULL,
    next_delivery DATETIME NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    UNIQUE (partition, account_id, region)
);

CREATE TABLE config_items (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    arn TEXT NOT NULL,
    availability_zone TEXT NOT NULL,
    capture_time DATETIME NOT NULL,
    creation_time DATETIME NOT NULL,
    status TEXT NOT NULL,
    configuration TEXT NOT NULL
);

CREATE TABLE config_deliveries (
    row_id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    id TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    object_key TEXT NOT NULL,
    due DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    completed_at DATETIME NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    first_sequence INTEGER NOT NULL,
    last_sequence INTEGER NOT NULL,
    UNIQUE (partition, account_id, region, id)
);

CREATE TABLE config_rules (
    row_id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    id TEXT NOT NULL,
    arn TEXT NOT NULL,
    description TEXT NOT NULL,
    owner TEXT NOT NULL,
    source_identifier TEXT NOT NULL,
    parameters_present BOOLEAN NOT NULL,
    resource_id TEXT NOT NULL,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    last_evaluation DATETIME NOT NULL,
    last_reevaluation DATETIME NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    UNIQUE (partition, account_id, region, name)
);

CREATE TABLE config_evaluations (
    row_id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    compliance_type TEXT NOT NULL,
    annotation TEXT NOT NULL,
    ordering_time DATETIME NOT NULL,
    recorded_at DATETIME NOT NULL,
    invoked_at DATETIME NOT NULL,
    UNIQUE (partition, account_id, region, rule_name, resource_type, resource_id)
);

CREATE TABLE config_evaluation_runs (
    row_id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    token TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    item_sequence INTEGER NOT NULL,
    due DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    completed_at DATETIME NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    UNIQUE (partition, account_id, region, token)
);

CREATE TABLE config_aggregators (
    row_id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    name TEXT NOT NULL,
    arn TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE (partition, account_id, region, name)
);

CREATE TABLE config_aggregation_authorizations (
    row_id INTEGER PRIMARY KEY,
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    authorized_account_id TEXT NOT NULL,
    authorized_region TEXT NOT NULL,
    arn TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE (partition, account_id, region, authorized_account_id, authorized_region)
);

CREATE TABLE config_recorder_types (
    parent_id INTEGER NOT NULL REFERENCES config_recorders(row_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    resource_type TEXT NOT NULL,
    PRIMARY KEY (parent_id, kind, ordinal)
);

CREATE TABLE config_item_tags (
    parent_id INTEGER NOT NULL REFERENCES config_items(sequence) ON DELETE CASCADE,
    tag_key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, tag_key)
);

CREATE TABLE config_item_supplementary (
    parent_id INTEGER NOT NULL REFERENCES config_items(sequence) ON DELETE CASCADE,
    name TEXT NOT NULL,
    document TEXT NOT NULL,
    PRIMARY KEY (parent_id, name)
);

CREATE TABLE config_item_relationships (
    parent_id INTEGER NOT NULL REFERENCES config_items(sequence) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    name TEXT NOT NULL,
    PRIMARY KEY (parent_id, ordinal)
);

CREATE TABLE config_rule_types (
    parent_id INTEGER NOT NULL REFERENCES config_rules(row_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    resource_type TEXT NOT NULL,
    PRIMARY KEY (parent_id, ordinal)
);

CREATE TABLE config_rule_messages (
    parent_id INTEGER NOT NULL REFERENCES config_rules(row_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY (parent_id, ordinal)
);

CREATE TABLE config_rule_parameters (
    parent_id INTEGER NOT NULL REFERENCES config_rules(row_id) ON DELETE CASCADE,
    parameter_key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (parent_id, parameter_key)
);

CREATE TABLE config_aggregator_sources (
    parent_id INTEGER NOT NULL REFERENCES config_aggregators(row_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    source_account_id TEXT NOT NULL,
    source_region TEXT NOT NULL,
    PRIMARY KEY (parent_id, ordinal)
);

CREATE INDEX config_item_scope_sequence ON config_items(partition, account_id, region, sequence);

CREATE INDEX config_evaluation_run_rule ON config_evaluation_runs(partition, account_id, region, rule_name);
