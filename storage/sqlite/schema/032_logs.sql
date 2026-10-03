CREATE TABLE logs_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 id TEXT NOT NULL UNIQUE,
 created INTEGER NOT NULL,
 sequence INTEGER NOT NULL,
 retention_days INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);
CREATE TABLE logs_tags (
 group_id TEXT NOT NULL REFERENCES logs_groups(id) ON DELETE CASCADE,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (group_id, key)
);
CREATE TABLE logs_streams (
 group_id TEXT NOT NULL REFERENCES logs_groups(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 id TEXT NOT NULL UNIQUE,
 created INTEGER NOT NULL,
 first_event INTEGER NOT NULL,
 last_event INTEGER NOT NULL,
 last_ingestion INTEGER NOT NULL,
 event_count INTEGER NOT NULL,
 PRIMARY KEY (group_id, name),
 UNIQUE (group_id, id)
);
CREATE INDEX logs_streams_last_event ON logs_streams(group_id, last_event, name);
CREATE TABLE logs_events (
 group_id TEXT NOT NULL,
 stream_id TEXT NOT NULL,
 stream_name TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 timestamp INTEGER NOT NULL,
 ingestion INTEGER NOT NULL,
 id TEXT NOT NULL,
 message TEXT NOT NULL,
 PRIMARY KEY (group_id, sequence),
 FOREIGN KEY (group_id, stream_id) REFERENCES logs_streams(group_id, id) ON DELETE CASCADE
);
CREATE INDEX logs_events_group_time ON logs_events(group_id, timestamp, ingestion, sequence);
CREATE INDEX logs_events_stream_time ON logs_events(stream_id, timestamp, ingestion, sequence);
