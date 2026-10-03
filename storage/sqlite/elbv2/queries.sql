-- name: GetLoadBalancer :one
SELECT * FROM elbv2_load_balancers WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: ListLoadBalancers :many
SELECT * FROM elbv2_load_balancers WHERE ((sqlc.arg(partition) = '' AND sqlc.arg(account_id) = '' AND sqlc.arg(region) = '') OR (partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region))) ORDER BY partition, account_id, region, arn;
-- name: PutLoadBalancer :exec
INSERT INTO elbv2_load_balancers (partition, account_id, region, arn, name, created, scheme, type, ip_address_type, vpc_id, dns_name, hosted_zone_id, state, state_reason, zones, security_groups, deletion_protection, idle_timeout, deleting, next_reconcile, version) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(name), sqlc.arg(created), sqlc.arg(scheme), sqlc.arg(type), sqlc.arg(ip_address_type), sqlc.arg(vpc_id), sqlc.arg(dns_name), sqlc.arg(hosted_zone_id), sqlc.arg(state), sqlc.arg(state_reason), sqlc.arg(zones), sqlc.arg(security_groups), sqlc.arg(deletion_protection), sqlc.arg(idle_timeout), sqlc.arg(deleting), sqlc.arg(next_reconcile), sqlc.arg(version)) ON CONFLICT (partition, account_id, region, arn) DO UPDATE SET name=excluded.name, created=excluded.created, scheme=excluded.scheme, type=excluded.type, ip_address_type=excluded.ip_address_type, vpc_id=excluded.vpc_id, dns_name=excluded.dns_name, hosted_zone_id=excluded.hosted_zone_id, state=excluded.state, state_reason=excluded.state_reason, zones=excluded.zones, security_groups=excluded.security_groups, deletion_protection=excluded.deletion_protection, idle_timeout=excluded.idle_timeout, deleting=excluded.deleting, next_reconcile=excluded.next_reconcile, version=excluded.version;
-- name: DeleteLoadBalancer :exec
DELETE FROM elbv2_load_balancers WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: GetTargetGroup :one
SELECT * FROM elbv2_target_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: ListTargetGroups :many
SELECT * FROM elbv2_target_groups WHERE ((sqlc.arg(partition) = '' AND sqlc.arg(account_id) = '' AND sqlc.arg(region) = '') OR (partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region))) ORDER BY partition, account_id, region, arn;
-- name: PutTargetGroup :exec
INSERT INTO elbv2_target_groups (partition, account_id, region, arn, name, protocol, port, protocol_version, target_type, ip_address_type, vpc_id, health_enabled, health_protocol, health_port, health_path, health_interval, health_timeout, healthy_threshold, unhealthy_threshold, matcher, load_balancer_arns, deregistration_delay) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(name), sqlc.arg(protocol), sqlc.arg(port), sqlc.arg(protocol_version), sqlc.arg(target_type), sqlc.arg(ip_address_type), sqlc.arg(vpc_id), sqlc.arg(health_enabled), sqlc.arg(health_protocol), sqlc.arg(health_port), sqlc.arg(health_path), sqlc.arg(health_interval), sqlc.arg(health_timeout), sqlc.arg(healthy_threshold), sqlc.arg(unhealthy_threshold), sqlc.arg(matcher), sqlc.arg(load_balancer_arns), sqlc.arg(deregistration_delay)) ON CONFLICT (partition, account_id, region, arn) DO UPDATE SET name=excluded.name, protocol=excluded.protocol, port=excluded.port, protocol_version=excluded.protocol_version, target_type=excluded.target_type, ip_address_type=excluded.ip_address_type, vpc_id=excluded.vpc_id, health_enabled=excluded.health_enabled, health_protocol=excluded.health_protocol, health_port=excluded.health_port, health_path=excluded.health_path, health_interval=excluded.health_interval, health_timeout=excluded.health_timeout, healthy_threshold=excluded.healthy_threshold, unhealthy_threshold=excluded.unhealthy_threshold, matcher=excluded.matcher, load_balancer_arns=excluded.load_balancer_arns, deregistration_delay=excluded.deregistration_delay;
-- name: DeleteTargetGroup :exec
DELETE FROM elbv2_target_groups WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: GetListener :one
SELECT * FROM elbv2_listeners WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: ListListeners :many
SELECT * FROM elbv2_listeners WHERE ((sqlc.arg(partition) = '' AND sqlc.arg(account_id) = '' AND sqlc.arg(region) = '') OR (partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region))) ORDER BY partition, account_id, region, arn;
-- name: PutListener :exec
INSERT INTO elbv2_listeners (partition, account_id, region, arn, load_balancer_arn, protocol, port, ssl_policy, certificate_id, certificates, actions) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(load_balancer_arn), sqlc.arg(protocol), sqlc.arg(port), sqlc.arg(ssl_policy), sqlc.arg(certificate_id), sqlc.arg(certificates), sqlc.arg(actions)) ON CONFLICT (partition, account_id, region, arn) DO UPDATE SET load_balancer_arn=excluded.load_balancer_arn, protocol=excluded.protocol, port=excluded.port, ssl_policy=excluded.ssl_policy, certificate_id=excluded.certificate_id, certificates=excluded.certificates, actions=excluded.actions;
-- name: DeleteListener :exec
DELETE FROM elbv2_listeners WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: GetRule :one
SELECT * FROM elbv2_rules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: ListRules :many
SELECT * FROM elbv2_rules WHERE ((sqlc.arg(partition) = '' AND sqlc.arg(account_id) = '' AND sqlc.arg(region) = '') OR (partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region))) ORDER BY partition, account_id, region, arn;
-- name: PutRule :exec
INSERT INTO elbv2_rules (partition, account_id, region, arn, listener_arn, priority, is_default, conditions, actions) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(listener_arn), sqlc.arg(priority), sqlc.arg(is_default), sqlc.arg(conditions), sqlc.arg(actions)) ON CONFLICT (partition, account_id, region, arn) DO UPDATE SET listener_arn=excluded.listener_arn, priority=excluded.priority, is_default=excluded.is_default, conditions=excluded.conditions, actions=excluded.actions;
-- name: DeleteRule :exec
DELETE FROM elbv2_rules WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: GetTarget :one
SELECT * FROM elbv2_targets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn) AND target_id = sqlc.arg(target_id) AND port = sqlc.arg(port);
-- name: ListTargets :many
SELECT * FROM elbv2_targets WHERE ((sqlc.arg(partition) = '' AND sqlc.arg(account_id) = '' AND sqlc.arg(region) = '') OR (partition=sqlc.arg(partition) AND account_id=sqlc.arg(account_id) AND region=sqlc.arg(region))) AND (sqlc.arg(arn) = '' OR arn=sqlc.arg(arn)) ORDER BY partition, account_id, region, arn, target_id, port;
-- name: PutTarget :exec
INSERT INTO elbv2_targets (partition, account_id, region, arn, target_id, port, availability_zone, owner_arn, incarnation, state, reason, description, successes, failures, next_check, drain_until, version) VALUES (sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(target_id), sqlc.arg(port), sqlc.arg(availability_zone), sqlc.arg(owner_arn), sqlc.arg(incarnation), sqlc.arg(state), sqlc.arg(reason), sqlc.arg(description), sqlc.arg(successes), sqlc.arg(failures), sqlc.arg(next_check), sqlc.arg(drain_until), sqlc.arg(version)) ON CONFLICT (partition, account_id, region, arn, target_id, port) DO UPDATE SET availability_zone=excluded.availability_zone, owner_arn=excluded.owner_arn, incarnation=excluded.incarnation, state=excluded.state, reason=excluded.reason, description=excluded.description, successes=excluded.successes, failures=excluded.failures, next_check=excluded.next_check, drain_until=excluded.drain_until, version=excluded.version;
-- name: DeleteTarget :exec
DELETE FROM elbv2_targets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn) AND target_id = sqlc.arg(target_id) AND port = sqlc.arg(port);
-- name: NextID :one
UPDATE elbv2_sequence SET value=value+1 WHERE id=1 RETURNING value;
-- name: ListTags :many
SELECT key,value FROM elbv2_tags WHERE partition=? AND account_id=? AND region=? AND arn=? ORDER BY key;
-- name: DeleteTags :exec
DELETE FROM elbv2_tags WHERE partition=? AND account_id=? AND region=? AND arn=?;
-- name: PutTag :exec
INSERT INTO elbv2_tags(partition,account_id,region,arn,key,value) VALUES(?,?,?,?,?,?);
-- name: ListAttachments :many
SELECT subnet_id,interface_id,generation FROM elbv2_attachments WHERE partition=? AND account_id=? AND region=? AND arn=? ORDER BY subnet_id;
-- name: DeleteAttachments :exec
DELETE FROM elbv2_attachments WHERE partition=? AND account_id=? AND region=? AND arn=?;
-- name: PutAttachment :exec
INSERT INTO elbv2_attachments(partition,account_id,region,arn,subnet_id,interface_id,generation) VALUES(?,?,?,?,?,?,?);

-- name: NextMetricPublication :one
SELECT partition, account_id, region, load_balancer_arn, due FROM elbv2_metric_samples ORDER BY due, load_balancer_arn LIMIT 1;
-- name: ListMetricSamples :many
SELECT name, target_group_arn, availability_zone, minimum, maximum, sum, count FROM elbv2_metric_samples WHERE partition=? AND account_id=? AND region=? AND load_balancer_arn=? AND due=? ORDER BY name, target_group_arn, availability_zone;
-- name: AddMetricSample :exec
INSERT INTO elbv2_metric_samples (partition, account_id, region, load_balancer_arn, due, name, target_group_arn, availability_zone, minimum, maximum, sum, count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account_id, region, load_balancer_arn, due, name, target_group_arn, availability_zone)
DO UPDATE SET minimum=MIN(minimum, excluded.minimum), maximum=MAX(maximum, excluded.maximum), sum=sum+excluded.sum, count=count+excluded.count;
-- name: DeleteMetricPublication :exec
DELETE FROM elbv2_metric_samples WHERE partition=? AND account_id=? AND region=? AND load_balancer_arn=? AND due=?;
-- name: SetNextMetricAt :exec
UPDATE elbv2_load_balancers SET next_metric_at=? WHERE partition=? AND account_id=? AND region=? AND arn=?;
