CREATE TABLE sns_topic_feedback (
    topic_id TEXT NOT NULL REFERENCES sns_topics(id) ON DELETE CASCADE ON UPDATE CASCADE,
    protocol TEXT NOT NULL,
    success_role_arn TEXT NOT NULL,
    failure_role_arn TEXT NOT NULL,
    success_sample_rate INTEGER,
    PRIMARY KEY (topic_id, protocol)
);
