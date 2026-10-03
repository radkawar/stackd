CREATE TABLE pipes_kafka_sources (
 pipe_id TEXT PRIMARY KEY REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 topic TEXT NOT NULL,
 consumer_group_id TEXT NOT NULL,
 authentication TEXT NOT NULL,
 secret_arn TEXT NOT NULL,
 root_ca_secret_arn TEXT NOT NULL
);
CREATE TABLE pipes_kafka_bootstrap_servers (
 pipe_id TEXT NOT NULL REFERENCES pipes_kafka_sources(pipe_id) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 address TEXT NOT NULL,
 PRIMARY KEY(pipe_id,position)
);
ALTER TABLE pipes_work ADD COLUMN filtered INTEGER NOT NULL DEFAULT 0;
CREATE TABLE pipes_kafka_identities (
 pipe_id TEXT PRIMARY KEY REFERENCES pipes_pipes(id) ON DELETE CASCADE,
 cluster_id TEXT NOT NULL,
 topic_id TEXT NOT NULL
);
