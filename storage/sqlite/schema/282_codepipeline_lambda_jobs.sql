-- Retained Lambda callbacks outlive pipeline deletion and action retries. Jobs
-- reference immutable action IDs, not the replace-on-save action row's lifetime.
CREATE TABLE codepipeline_invocation_jobs (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    job_id TEXT NOT NULL,
    pipeline_name TEXT NOT NULL,
    incarnation TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    stage_name TEXT NOT NULL,
    result_continuation_token TEXT NOT NULL,
    action_name TEXT NOT NULL,
    status TEXT NOT NULL,
    continuation_token TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    action_expires_at INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    execution_details_present INTEGER NOT NULL,
    execution_external_id TEXT,
    execution_percent INTEGER,
    execution_summary TEXT,
    failure_details_present INTEGER NOT NULL,
    failure_external_id TEXT,
    failure_message TEXT,
    failure_type TEXT,
    current_revision_present INTEGER NOT NULL,
    revision_change_id TEXT,
    revision_created INTEGER,
    revision_id TEXT,
    revision_summary TEXT,
    output_variables_present INTEGER NOT NULL,
    PRIMARY KEY (partition, account_id, region, job_id),
    UNIQUE (partition, account_id, region, action_id, sequence)
);
CREATE INDEX codepipeline_invocation_jobs_action
    ON codepipeline_invocation_jobs (partition, account_id, region, action_id, sequence);

CREATE TABLE codepipeline_invocation_job_variables (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    job_id TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, account_id, region, job_id, name)
);
