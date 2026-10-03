ALTER TABLE ecs_services ADD COLUMN next_metric_collection TIMESTAMP NOT NULL DEFAULT '0001-01-01T00:00:00Z';
ALTER TABLE ecs_service_deployments ADD COLUMN monitoring BLOB NOT NULL DEFAULT X'6e756c6c';

-- Names are CloudWatch dimensions, not cascading resource references. Completed
-- observations remain publishable after service deletion or recreation.
CREATE TABLE ecs_service_metric_samples (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 cluster_name TEXT NOT NULL, service_name TEXT NOT NULL, due TIMESTAMP NOT NULL,
 metric_name TEXT NOT NULL, task_id TEXT NOT NULL, resolution_seconds INTEGER NOT NULL,
 minimum REAL NOT NULL, maximum REAL NOT NULL,
 observation_sum REAL NOT NULL, observation_count INTEGER NOT NULL,
 PRIMARY KEY(partition, account_id, region, cluster_name, service_name, due, metric_name, task_id, resolution_seconds)
);
CREATE INDEX ecs_service_metric_samples_due ON ecs_service_metric_samples(due, partition, account_id, region, cluster_name, service_name);
CREATE INDEX ecs_tasks_service ON ecs_tasks(partition, account_id, region, cluster_name, service_name, task_id);
