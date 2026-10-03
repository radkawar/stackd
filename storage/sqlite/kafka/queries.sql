-- name: GetCluster :one
SELECT * FROM msk_clusters WHERE arn = ?;
-- name: PutCluster :exec
INSERT INTO msk_clusters (arn,partition,account_id,region,name,incarnation,kafka_version,security_mode,state,failure,operation,operation_arn,configuration_arn,pending_configuration_arn,configuration_revision,pending_configuration_revision,server_properties,pending_server_properties,brokers,version,created,due,capem,policy_document,policy_version,reboot_broker_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,name=excluded.name,incarnation=excluded.incarnation,kafka_version=excluded.kafka_version,security_mode=excluded.security_mode,state=excluded.state,failure=excluded.failure,operation=excluded.operation,operation_arn=excluded.operation_arn,configuration_arn=excluded.configuration_arn,pending_configuration_arn=excluded.pending_configuration_arn,configuration_revision=excluded.configuration_revision,pending_configuration_revision=excluded.pending_configuration_revision,server_properties=excluded.server_properties,pending_server_properties=excluded.pending_server_properties,brokers=excluded.brokers,version=excluded.version,created=excluded.created,due=excluded.due,capem=excluded.capem,policy_document=excluded.policy_document,policy_version=excluded.policy_version,reboot_broker_id=excluded.reboot_broker_id;
-- name: DeleteCluster :exec
DELETE FROM msk_clusters WHERE arn = ?;
-- name: AllClusters :many
SELECT * FROM msk_clusters ORDER BY arn;
-- name: ListClusters :many
SELECT * FROM msk_clusters WHERE partition = ? AND account_id = ? AND region = ? ORDER BY arn;
-- name: GetConfiguration :one
SELECT * FROM msk_configurations WHERE arn = ?;
-- name: PutConfiguration :exec
INSERT INTO msk_configurations (arn,partition,account_id,region,name,description,created,latest_revision) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,name=excluded.name,description=excluded.description,created=excluded.created,latest_revision=excluded.latest_revision;
-- name: DeleteConfiguration :exec
DELETE FROM msk_configurations WHERE arn = ?;
-- name: ListConfigurations :many
SELECT * FROM msk_configurations WHERE partition = ? AND account_id = ? AND region = ? ORDER BY arn;
-- name: GetRevision :one
SELECT * FROM msk_revisions WHERE arn = ? AND revision = ?;
-- name: PutRevision :exec
INSERT INTO msk_revisions (arn,revision,description,server_properties,created) VALUES (?,?,?,?,?) ON CONFLICT (arn,revision) DO UPDATE SET description=excluded.description,server_properties=excluded.server_properties,created=excluded.created;
-- name: DeleteRevision :exec
DELETE FROM msk_revisions WHERE arn = ?;
-- name: ListRevisions :many
SELECT * FROM msk_revisions WHERE arn = ? ORDER BY revision;
-- name: GetOperation :one
SELECT * FROM msk_operations WHERE arn = ?;
-- name: PutOperation :exec
INSERT INTO msk_operations (arn,partition,account_id,region,cluster_arn,type,state,failure,source_configuration_arn,target_configuration_arn,source_revision,target_revision,created,ended) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (arn) DO UPDATE SET partition=excluded.partition,account_id=excluded.account_id,region=excluded.region,cluster_arn=excluded.cluster_arn,type=excluded.type,state=excluded.state,failure=excluded.failure,source_configuration_arn=excluded.source_configuration_arn,target_configuration_arn=excluded.target_configuration_arn,source_revision=excluded.source_revision,target_revision=excluded.target_revision,created=excluded.created,ended=excluded.ended;
-- name: ListOperations :many
SELECT * FROM msk_operations WHERE cluster_arn = ? ORDER BY arn;
-- name: ListClusterTags :many
SELECT * FROM msk_cluster_tags WHERE arn = ? ORDER BY tag_key;
-- name: DeleteClusterTags :exec
DELETE FROM msk_cluster_tags WHERE arn = ?;
-- name: PutClusterTag :exec
INSERT INTO msk_cluster_tags (arn,tag_key,tag_value) VALUES (?,?,?);
-- name: ListClusterSecrets :many
SELECT * FROM msk_cluster_secrets WHERE arn = ? ORDER BY secret_arn;
-- name: DeleteClusterSecrets :exec
DELETE FROM msk_cluster_secrets WHERE arn = ?;
-- name: PutClusterSecret :exec
INSERT INTO msk_cluster_secrets (arn,secret_arn) VALUES (?,?);
-- name: ListClusterBrokers :many
SELECT * FROM msk_cluster_brokers WHERE arn = ? ORDER BY broker_id;
-- name: DeleteClusterBrokers :exec
DELETE FROM msk_cluster_brokers WHERE arn = ?;
-- name: PutClusterBroker :exec
INSERT INTO msk_cluster_brokers (arn,broker_id,address) VALUES (?,?,?);
-- name: ListPolicyPrincipals :many
SELECT * FROM msk_policy_principals WHERE arn = ? ORDER BY principal_arn;
-- name: DeletePolicyPrincipals :exec
DELETE FROM msk_policy_principals WHERE arn = ?;
-- name: PutPolicyPrincipal :exec
INSERT INTO msk_policy_principals (arn,principal_arn,principal_id) VALUES (?,?,?);
-- name: ListConfigurationVersions :many
SELECT * FROM msk_configuration_versions WHERE arn = ? ORDER BY kafka_version;
-- name: DeleteConfigurationVersions :exec
DELETE FROM msk_configuration_versions WHERE arn = ?;
-- name: PutConfigurationVersion :exec
INSERT INTO msk_configuration_versions (arn,kafka_version) VALUES (?,?);
