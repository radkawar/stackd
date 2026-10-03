CREATE TABLE eventbridge_buses (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
    description TEXT NOT NULL,
    created TIMESTAMP NOT NULL, modified TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, region, name)
);
CREATE TABLE eventbridge_bus_tags (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, bus_name TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, bus_name, key),
    FOREIGN KEY (partition, account, region, bus_name) REFERENCES eventbridge_buses(partition, account, region, name) ON DELETE CASCADE
);
CREATE TABLE eventbridge_rules (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, bus_name TEXT NOT NULL, name TEXT NOT NULL,
    pattern TEXT NOT NULL, description TEXT NOT NULL, state TEXT NOT NULL, created_by TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, bus_name, name),
    FOREIGN KEY (partition, account, region, bus_name) REFERENCES eventbridge_buses(partition, account, region, name) ON DELETE CASCADE
);
CREATE TABLE eventbridge_rule_tags (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, bus_name TEXT NOT NULL, rule_name TEXT NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, bus_name, rule_name, key),
    FOREIGN KEY (partition, account, region, bus_name, rule_name) REFERENCES eventbridge_rules(partition, account, region, bus_name, name) ON DELETE CASCADE
);
CREATE TABLE eventbridge_targets (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, bus_name TEXT NOT NULL, rule_name TEXT NOT NULL, id TEXT NOT NULL,
    arn TEXT NOT NULL, input TEXT NOT NULL, has_input BOOLEAN NOT NULL,
    message_group_id TEXT NOT NULL, dead_letter_arn TEXT NOT NULL,
    max_retries INTEGER NOT NULL, max_age_seconds INTEGER NOT NULL,
    has_retry_policy BOOLEAN NOT NULL, has_max_retries BOOLEAN NOT NULL, has_max_age BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account, region, bus_name, rule_name, id),
    FOREIGN KEY (partition, account, region, bus_name, rule_name) REFERENCES eventbridge_rules(partition, account, region, bus_name, name) ON DELETE CASCADE
);
CREATE TABLE eventbridge_events (
    id TEXT PRIMARY KEY,
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, bus_name TEXT NOT NULL,
    source TEXT NOT NULL, detail_type TEXT NOT NULL, detail TEXT NOT NULL,
    event_time TIMESTAMP NOT NULL, accepted TIMESTAMP NOT NULL,
    producer_account TEXT NOT NULL, request_id TEXT NOT NULL, actor_arn TEXT NOT NULL
);
CREATE TABLE eventbridge_event_resources (
    event_id TEXT NOT NULL REFERENCES eventbridge_events(id) ON DELETE CASCADE,
    position INTEGER NOT NULL, arn TEXT NOT NULL,
    PRIMARY KEY (event_id, position)
);
CREATE TABLE eventbridge_deliveries (
    id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES eventbridge_events(id),
    rule_arn TEXT NOT NULL, target_id TEXT NOT NULL, target_arn TEXT NOT NULL,
    input TEXT NOT NULL, has_input BOOLEAN NOT NULL, message_group_id TEXT NOT NULL, dead_letter_arn TEXT NOT NULL,
    max_retries INTEGER NOT NULL, max_age_seconds INTEGER NOT NULL, attempts INTEGER NOT NULL,
    due TIMESTAMP NOT NULL, version INTEGER NOT NULL,
    state TEXT NOT NULL, last_error_code TEXT NOT NULL, last_error_message TEXT NOT NULL, exhausted_retry_condition TEXT NOT NULL
);
CREATE INDEX eventbridge_pending_deliveries ON eventbridge_deliveries(due, id) WHERE state IN ('pending', 'dead-letter');
