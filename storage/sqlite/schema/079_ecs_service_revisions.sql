-- Execution snapshots remain authoritative while a deployment owns tasks or a
-- rollback baseline. Retired revisions retain only their public configuration.
-- Service deletion clears these rows before the same service name can be reused.
CREATE TABLE ecs_service_revisions (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 cluster_name TEXT NOT NULL,
 service_name TEXT NOT NULL,
 revision_id TEXT NOT NULL,
 created_at TIMESTAMP,
 task_definition TEXT,
 launch_type TEXT,
 platform_family TEXT,
 platform_version TEXT,
 guard_duty_enabled BOOLEAN,
 capacity_provider_strategy BLOB NOT NULL,
 container_images BLOB NOT NULL,
 ecs_managed_resources BLOB NOT NULL,
 fargate_ephemeral_storage BLOB NOT NULL,
 load_balancers BLOB NOT NULL,
 monitoring BLOB NOT NULL,
 network_configuration BLOB NOT NULL,
 overrides BLOB NOT NULL,
 resolved_configuration BLOB NOT NULL,
 service_connect_configuration BLOB NOT NULL,
 service_registries BLOB NOT NULL,
 volume_configurations BLOB NOT NULL,
 vpc_lattice_configurations BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, cluster_name, service_name, revision_id),
 FOREIGN KEY (partition, account_id, region, cluster_name, service_name) REFERENCES ecs_services(partition, account_id, region, cluster_name, service_name) ON DELETE CASCADE
);
