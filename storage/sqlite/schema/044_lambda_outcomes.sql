ALTER TABLE lambda_functions ADD COLUMN dead_letter_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_event_invoke_configs ADD COLUMN on_success_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_event_invoke_configs ADD COLUMN on_failure_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_event_invoke_configs ADD COLUMN effective_on_success_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_event_invoke_configs ADD COLUMN effective_on_failure_arn TEXT NOT NULL DEFAULT '';

-- Completed invocations retain their source identity without owning a live
-- deployment. The repository deletes only queued/in-flight work with a function.
ALTER TABLE lambda_invocations RENAME TO lambda_invocations_legacy;
CREATE TABLE lambda_invocations (
    id TEXT PRIMARY KEY,
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    function_arn TEXT NOT NULL, payload BLOB NOT NULL,
    request_id TEXT NOT NULL, parent_event_id TEXT NOT NULL,
    accepted TIMESTAMP NOT NULL, due TIMESTAMP NOT NULL,
    version INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('queued', 'in-flight', 'completed')),
    invoke_count INTEGER NOT NULL, system_errors INTEGER NOT NULL,
    response_payload BLOB, response_error TEXT NOT NULL DEFAULT '',
    response_status INTEGER NOT NULL DEFAULT 0, response_version TEXT NOT NULL DEFAULT '',
    completed TIMESTAMP NOT NULL DEFAULT '0001-01-01T00:00:00Z',
    completion TEXT NOT NULL DEFAULT '', role_arn TEXT NOT NULL DEFAULT ''
);
-- Old retries counted failed runtime responses, but did not retain their bodies.
-- Preserve those counts without fabricating a response for upgraded records.
INSERT INTO lambda_invocations (
    id, partition, account, region, function_name, function_arn, payload,
    request_id, parent_event_id, accepted, due, version, state, invoke_count, system_errors
)
SELECT id, partition, account, region, function_name, function_arn, payload,
    request_id, parent_event_id, accepted, due, version, state, function_errors, system_errors
FROM lambda_invocations_legacy;
DROP TABLE lambda_invocations_legacy;
CREATE INDEX lambda_invocations_due ON lambda_invocations(state, due, id);
CREATE UNIQUE INDEX lambda_invocations_in_flight ON lambda_invocations(partition, account, region, function_name) WHERE state = 'in-flight';

CREATE TABLE lambda_outcome_deliveries (
    id TEXT PRIMARY KEY,
    invocation_id TEXT NOT NULL REFERENCES lambda_invocations(id) ON DELETE CASCADE,
    destination_arn TEXT NOT NULL,
    dead_letter BOOLEAN NOT NULL
);
CREATE INDEX lambda_outcome_deliveries_invocation ON lambda_outcome_deliveries(invocation_id);
CREATE INDEX lambda_invocations_completed ON lambda_invocations(completed, id) WHERE state = 'completed';

-- Function identity is a metric dimension, not a cascading foreign key.
CREATE TABLE lambda_metric_samples (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    minute TIMESTAMP NOT NULL, metric_name TEXT NOT NULL,
    value INTEGER NOT NULL, sample_count INTEGER NOT NULL,
    PRIMARY KEY (partition, account, region, function_name, minute, metric_name, value)
);
CREATE INDEX lambda_metric_samples_due ON lambda_metric_samples(minute, partition, account, region, function_name);
