-- Finish time belongs to the native rollout transition, not mutable UpdatedAt.
ALTER TABLE ecs_service_deployments ADD COLUMN finished_at TIMESTAMP;
ALTER TABLE ecs_services ADD COLUMN deployment_history_present BOOLEAN NOT NULL DEFAULT FALSE;

-- Retired read projections relinquish all task execution and definition ownership.
-- Only the generated nested revision summary is JSON; resources are scalar rows.
CREATE TABLE ecs_service_deployment_history (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 cluster_name TEXT NOT NULL,
 service_name TEXT NOT NULL,
 position INTEGER NOT NULL,
 service_deployment_arn TEXT,
 service_arn TEXT,
 cluster_arn TEXT,
 created_at TIMESTAMP,
 started_at TIMESTAMP,
 updated_at TIMESTAMP,
 finished_at TIMESTAMP,
 stopped_at TIMESTAMP,
 status TEXT,
 status_reason TEXT,
 target_service_revision BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, cluster_name, service_name, position),
 FOREIGN KEY (partition, account_id, region, cluster_name, service_name)
  REFERENCES ecs_services(partition, account_id, region, cluster_name, service_name) ON DELETE CASCADE
);
