-- ALB resources and exact target incarnation/health/drain intent. Native sockets and EC2 policy remain externally owned.
CREATE TABLE elbv2_load_balancers (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 arn TEXT NOT NULL,
 name TEXT NOT NULL,
 created INTEGER NOT NULL,
 scheme TEXT NOT NULL,
 type TEXT NOT NULL,
 ip_address_type TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 dns_name TEXT NOT NULL,
 hosted_zone_id TEXT NOT NULL,
 state TEXT NOT NULL,
 state_reason TEXT NOT NULL,
 zones BLOB NOT NULL,
 security_groups BLOB NOT NULL,
 deletion_protection INTEGER NOT NULL,
 idle_timeout INTEGER NOT NULL,
 deleting INTEGER NOT NULL,
 next_reconcile INTEGER NOT NULL,
 version INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, arn)
);
CREATE TABLE elbv2_target_groups (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 arn TEXT NOT NULL,
 name TEXT NOT NULL,
 protocol TEXT NOT NULL,
 port INTEGER NOT NULL,
 protocol_version TEXT NOT NULL,
 target_type TEXT NOT NULL,
 ip_address_type TEXT NOT NULL,
 vpc_id TEXT NOT NULL,
 health_enabled INTEGER NOT NULL,
 health_protocol TEXT NOT NULL,
 health_port TEXT NOT NULL,
 health_path TEXT NOT NULL,
 health_interval INTEGER NOT NULL,
 health_timeout INTEGER NOT NULL,
 healthy_threshold INTEGER NOT NULL,
 unhealthy_threshold INTEGER NOT NULL,
 matcher TEXT NOT NULL,
 load_balancer_arns BLOB NOT NULL,
 deregistration_delay INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, arn)
);
CREATE TABLE elbv2_listeners (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 arn TEXT NOT NULL,
 load_balancer_arn TEXT NOT NULL,
 protocol TEXT NOT NULL,
 port INTEGER NOT NULL,
 ssl_policy TEXT NOT NULL,
 certificate_id TEXT NOT NULL,
 certificates BLOB NOT NULL,
 actions BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, arn)
);
CREATE TABLE elbv2_rules (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 arn TEXT NOT NULL,
 listener_arn TEXT NOT NULL,
 priority TEXT NOT NULL,
 is_default INTEGER NOT NULL,
 conditions BLOB NOT NULL,
 actions BLOB NOT NULL,
 PRIMARY KEY (partition, account_id, region, arn)
);
CREATE TABLE elbv2_targets (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 arn TEXT NOT NULL,
 target_id TEXT NOT NULL,
 port INTEGER NOT NULL,
 availability_zone TEXT NOT NULL,
 owner_arn TEXT NOT NULL,
 incarnation TEXT NOT NULL,
 state TEXT NOT NULL,
 reason TEXT NOT NULL,
 description TEXT NOT NULL,
 successes INTEGER NOT NULL,
 failures INTEGER NOT NULL,
 next_check INTEGER NOT NULL,
 drain_until INTEGER NOT NULL,
 version INTEGER NOT NULL,
 PRIMARY KEY (partition, account_id, region, arn, target_id, port)
);
CREATE TABLE elbv2_tags (partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, arn TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(partition,account_id,region,arn,key));
CREATE TABLE elbv2_attachments (partition TEXT NOT NULL,account_id TEXT NOT NULL,region TEXT NOT NULL,arn TEXT NOT NULL,subnet_id TEXT NOT NULL,interface_id TEXT NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(partition,account_id,region,arn,subnet_id));
CREATE TABLE elbv2_sequence (id INTEGER PRIMARY KEY CHECK(id=1), value INTEGER NOT NULL);
INSERT INTO elbv2_sequence(id,value) VALUES(1,0);
ALTER TABLE ecs_service_deployments ADD COLUMN load_balancers BLOB NOT NULL DEFAULT '[]';
