-- name: GetDomain :one
SELECT * FROM apigatewayv2_domains WHERE partition=? AND account_id=? AND region=? AND name=?;
-- name: GetDomainByHost :one
SELECT * FROM apigatewayv2_domains WHERE name=?;
-- name: ListDomains :many
SELECT * FROM apigatewayv2_domains WHERE partition=? AND account_id=? AND region=? ORDER BY name;
-- name: PutDomain :exec
INSERT INTO apigatewayv2_domains(partition,account_id,region,name,owner_stack_id,owner_logical_id,owner_token,certificate_arn,certificate_id,certificate_name,ownership_certificate_arn,ownership_certificate_id,security_policy,ip_address_type,truststore_uri,truststore_version,truststore_pem,tags) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,name) DO UPDATE SET owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token,certificate_arn=excluded.certificate_arn,certificate_id=excluded.certificate_id,certificate_name=excluded.certificate_name,ownership_certificate_arn=excluded.ownership_certificate_arn,ownership_certificate_id=excluded.ownership_certificate_id,security_policy=excluded.security_policy,ip_address_type=excluded.ip_address_type,truststore_uri=excluded.truststore_uri,truststore_version=excluded.truststore_version,truststore_pem=excluded.truststore_pem,tags=excluded.tags;
-- name: DeleteDomain :exec
DELETE FROM apigatewayv2_domains WHERE partition=? AND account_id=? AND region=? AND name=?;
-- name: GetMapping :one
SELECT * FROM apigatewayv2_mappings WHERE partition=? AND account_id=? AND region=? AND domain_name=? AND id=?;
-- name: ListMappings :many
SELECT * FROM apigatewayv2_mappings WHERE partition=? AND account_id=? AND region=? AND domain_name=? ORDER BY id;
-- name: PutMapping :exec
INSERT INTO apigatewayv2_mappings(partition,account_id,region,domain_name,id,owner_stack_id,owner_logical_id,owner_token,api_id,stage,path) VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,domain_name,id) DO UPDATE SET owner_stack_id=excluded.owner_stack_id,owner_logical_id=excluded.owner_logical_id,owner_token=excluded.owner_token,api_id=excluded.api_id,stage=excluded.stage,path=excluded.path;
-- name: DeleteMapping :exec
DELETE FROM apigatewayv2_mappings WHERE partition=? AND account_id=? AND region=? AND domain_name=? AND id=?;
