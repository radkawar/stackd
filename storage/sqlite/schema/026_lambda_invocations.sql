CREATE TABLE lambda_event_invoke_configs (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    pending BOOLEAN NOT NULL DEFAULT false CHECK (pending = false),
    modified TIMESTAMP NOT NULL,
    max_age_seconds INTEGER NOT NULL, max_retries INTEGER NOT NULL,
    has_max_age BOOLEAN NOT NULL, has_max_retries BOOLEAN NOT NULL,
    effective_max_age_seconds INTEGER NOT NULL, effective_max_retries INTEGER NOT NULL,
    applies_at TIMESTAMP, version INTEGER NOT NULL, deleted BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account, region, function_name),
    FOREIGN KEY (partition, account, region, function_name, pending) REFERENCES lambda_functions(partition, account, region, name, pending) ON DELETE CASCADE
);
CREATE INDEX lambda_event_invoke_configs_due ON lambda_event_invoke_configs(applies_at, partition, region, account, function_name) WHERE applies_at IS NOT NULL;
CREATE TABLE lambda_invocations (
    id TEXT PRIMARY KEY,
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    pending BOOLEAN NOT NULL DEFAULT false CHECK (pending = false),
    function_arn TEXT NOT NULL, payload BLOB NOT NULL,
    request_id TEXT NOT NULL, parent_event_id TEXT NOT NULL,
    accepted TIMESTAMP NOT NULL, due TIMESTAMP NOT NULL,
    version INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('queued', 'in-flight')),
    function_errors INTEGER NOT NULL, system_errors INTEGER NOT NULL,
    FOREIGN KEY (partition, account, region, function_name, pending) REFERENCES lambda_functions(partition, account, region, name, pending) ON DELETE CASCADE
);
CREATE INDEX lambda_invocations_due ON lambda_invocations(state, due, id);
CREATE UNIQUE INDEX lambda_invocations_in_flight ON lambda_invocations(partition, account, region, function_name) WHERE state = 'in-flight';
