ALTER TABLE codepipeline_pipelines ADD COLUMN polling_disabled_at INTEGER NOT NULL DEFAULT 0;

CREATE TABLE codepipeline_source_polls (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    incarnation TEXT NOT NULL,
    pipeline_name TEXT NOT NULL,
    pipeline_version INTEGER NOT NULL,
    stage_name TEXT NOT NULL,
    action_name TEXT NOT NULL,
    bucket TEXT NOT NULL,
    object_key TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    poll_id TEXT NOT NULL,
    parent_event_id TEXT NOT NULL,
    error_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    last_attempt INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    due INTEGER NOT NULL,
    PRIMARY KEY (partition, account_id, region, incarnation, stage_name, action_name)
);
CREATE INDEX codepipeline_source_polls_due ON codepipeline_source_polls(due) WHERE due != 0;
