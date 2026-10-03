ALTER TABLE xray_segments ADD COLUMN completed DATETIME;
ALTER TABLE xray_segments ADD COLUMN received_revision INTEGER NOT NULL DEFAULT 1;
ALTER TABLE xray_segments ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;
-- Previous schemas did not retain completion arrival separately from receipt.
UPDATE xray_segments SET completed = received WHERE in_progress = 0 AND end_time IS NOT NULL;
CREATE INDEX xray_segments_completed ON xray_segments(partition, account_id, region, completed);

CREATE TABLE xray_traces (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 trace_id TEXT NOT NULL,
 start_time REAL NOT NULL,
 end_time REAL NOT NULL,
 updated DATETIME NOT NULL,
 revision INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, trace_id)
);
CREATE INDEX xray_traces_start ON xray_traces(partition, account_id, region, start_time);
CREATE INDEX xray_traces_updated ON xray_traces(partition, account_id, region, updated);

-- Earlier schemas retained documents but did not expose discovery revisions.
-- Existing traces enter the newly introduced discovery index at revision one.
INSERT INTO xray_traces
SELECT partition, account_id, region, trace_id, MIN(start_time),
 MAX(COALESCE(end_time, start_time)), MAX(received), 1
FROM xray_segments GROUP BY partition, account_id, region, trace_id;

CREATE TABLE xray_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL,
 name TEXT NOT NULL,
 filter_expression TEXT NOT NULL,
 version INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, id)
);
CREATE UNIQUE INDEX xray_groups_name ON xray_groups(partition, account_id, region, name);

CREATE TABLE xray_group_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_id TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, group_id, key),
 FOREIGN KEY (partition, account_id, region, group_id)
 REFERENCES xray_groups(partition, account_id, region, id) ON DELETE CASCADE
);

CREATE TABLE xray_group_traces (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_id TEXT NOT NULL,
 trace_id TEXT NOT NULL,
 version INTEGER NOT NULL,
 admitted DATETIME NOT NULL,
 admitted_revision INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, group_id, trace_id),
 FOREIGN KEY (partition, account_id, region, group_id)
 REFERENCES xray_groups(partition, account_id, region, id) ON DELETE CASCADE,
 FOREIGN KEY (partition, account_id, region, trace_id)
 REFERENCES xray_traces(partition, account_id, region, trace_id) ON DELETE CASCADE
);

CREATE TABLE xray_group_metrics (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 group_id TEXT NOT NULL,
 group_name TEXT NOT NULL,
 minute DATETIME NOT NULL,
 count INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, group_id, minute)
);
CREATE INDEX xray_group_metrics_due ON xray_group_metrics(minute);
