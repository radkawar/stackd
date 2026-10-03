CREATE TABLE cloudwatch_dashboards (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 name TEXT NOT NULL,
 body TEXT NOT NULL,
 updated TIMESTAMP NOT NULL,
 size INTEGER NOT NULL,
 tagging_initialized BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, name)
);
CREATE TABLE cloudwatch_dashboard_tags (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 dashboard_name TEXT NOT NULL,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, dashboard_name, key),
 FOREIGN KEY (partition, account_id, dashboard_name)
  REFERENCES cloudwatch_dashboards(partition, account_id, name) ON DELETE CASCADE
);
