CREATE TABLE cloudwatch_metrics (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 namespace TEXT NOT NULL,
 name TEXT NOT NULL,
 dimensions TEXT NOT NULL,
 id TEXT NOT NULL UNIQUE,
 created TIMESTAMP NOT NULL,
 published_at TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, namespace, name, dimensions)
);
CREATE TABLE cloudwatch_dimensions (
 metric_id TEXT NOT NULL REFERENCES cloudwatch_metrics(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (metric_id, name)
);
CREATE TABLE cloudwatch_points (
 sequence INTEGER PRIMARY KEY,
 metric_id TEXT NOT NULL REFERENCES cloudwatch_metrics(id) ON DELETE CASCADE,
 timestamp INTEGER NOT NULL,
 unit TEXT NOT NULL,
 resolution INTEGER NOT NULL,
 sample_count REAL NOT NULL,
 sum REAL NOT NULL,
 minimum REAL NOT NULL,
 maximum REAL NOT NULL,
 raw BOOLEAN NOT NULL
);
CREATE INDEX cloudwatch_points_publication ON cloudwatch_points(metric_id, sequence);
CREATE INDEX cloudwatch_points_time ON cloudwatch_points(metric_id, timestamp, sequence);
