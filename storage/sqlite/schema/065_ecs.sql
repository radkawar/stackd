-- Authoritative state is independent of the admitted CreateCluster arguments.
-- INACTIVE clusters and DELETE_IN_PROGRESS task definitions remain addressable.
CREATE TABLE ecs_clusters (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 cluster_arn TEXT, cluster_name TEXT, status TEXT,
 active_services_count INTEGER, pending_tasks_count INTEGER,
 registered_container_instances_count INTEGER, running_tasks_count INTEGER,
 attachments_status TEXT,
 attachments BLOB NOT NULL, configuration BLOB NOT NULL,
 default_capacity_provider_strategy BLOB NOT NULL,
 service_connect_defaults BLOB NOT NULL, settings BLOB NOT NULL, statistics BLOB NOT NULL,
 capacity_providers_present BOOLEAN NOT NULL,
 created TIMESTAMP NOT NULL, updated TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, name)
);
CREATE INDEX ecs_clusters_status ON ecs_clusters(partition, account_id, region, status, name);
CREATE TABLE ecs_cluster_create_inputs (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 cluster_name TEXT, configuration BLOB NOT NULL, default_capacity_provider_strategy BLOB NOT NULL,
 service_connect_defaults BLOB NOT NULL, settings BLOB NOT NULL,
 capacity_providers_present BOOLEAN NOT NULL, tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, name),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES ecs_clusters(partition, account_id, region, name) ON DELETE CASCADE
);
CREATE TABLE ecs_cluster_capacity_providers (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 original BOOLEAN NOT NULL, position INTEGER NOT NULL, provider TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, original, position),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES ecs_clusters(partition, account_id, region, name) ON DELETE CASCADE
);
-- These are creation arguments, not a second copy of the current resource tags.
CREATE TABLE ecs_cluster_create_tags (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 position INTEGER NOT NULL, key TEXT, value TEXT,
 PRIMARY KEY (partition, account_id, region, name, position),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES ecs_cluster_create_inputs(partition, account_id, region, name) ON DELETE CASCADE
);
-- Counters have no resource foreign key: deletion cannot reset family history.
CREATE TABLE ecs_task_definition_revisions (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, family TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 2147483647),
 PRIMARY KEY (partition, account_id, region, family)
);
CREATE TABLE ecs_task_definitions (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, family TEXT NOT NULL, revision INTEGER NOT NULL,
 task_definition_arn TEXT, task_family TEXT, task_revision INTEGER, status TEXT,
 cpu TEXT, memory TEXT, network_mode TEXT, ipc_mode TEXT, pid_mode TEXT,
 execution_role_arn TEXT, task_role_arn TEXT, registered_by TEXT,
 registered_at TIMESTAMP, deregistered_at TIMESTAMP, delete_requested_at TIMESTAMP,
 enable_fault_injection BOOLEAN,
 container_definitions BLOB NOT NULL, ephemeral_storage BLOB NOT NULL,
 inference_accelerators BLOB NOT NULL, placement_constraints BLOB NOT NULL,
 proxy_configuration BLOB NOT NULL, requires_attributes BLOB NOT NULL,
 runtime_platform BLOB NOT NULL, volumes BLOB NOT NULL,
 compatibilities_present BOOLEAN NOT NULL, requires_compatibilities_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, family, revision)
);
CREATE INDEX ecs_task_definitions_status ON ecs_task_definitions(partition, account_id, region, status, family, revision);
CREATE TABLE ecs_task_definition_compatibilities (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, family TEXT NOT NULL, revision INTEGER NOT NULL,
 required BOOLEAN NOT NULL, position INTEGER NOT NULL, compatibility TEXT NOT NULL,
 PRIMARY KEY (partition, account_id, region, family, revision, required, position),
 FOREIGN KEY (partition, account_id, region, family, revision) REFERENCES ecs_task_definitions(partition, account_id, region, family, revision) ON DELETE CASCADE
);
CREATE TABLE ecs_tag_sets (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, resource_arn TEXT NOT NULL,
 tags_present BOOLEAN NOT NULL,
 PRIMARY KEY (partition, account_id, region, resource_arn)
);
CREATE TABLE ecs_tags (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, resource_arn TEXT NOT NULL,
 position INTEGER NOT NULL, key TEXT, value TEXT,
 PRIMARY KEY (partition, account_id, region, resource_arn, position),
 FOREIGN KEY (partition, account_id, region, resource_arn) REFERENCES ecs_tag_sets(partition, account_id, region, resource_arn) ON DELETE CASCADE
);
