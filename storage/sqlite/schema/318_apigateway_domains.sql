CREATE TABLE apigatewayv2_domains (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL UNIQUE,
 owner_stack_id TEXT NOT NULL, owner_logical_id TEXT NOT NULL, owner_token TEXT NOT NULL,
 certificate_arn TEXT NOT NULL, certificate_id TEXT NOT NULL, certificate_name TEXT NOT NULL,
 ownership_certificate_arn TEXT NOT NULL, ownership_certificate_id TEXT NOT NULL,
 security_policy TEXT NOT NULL, ip_address_type TEXT NOT NULL,
 truststore_uri TEXT NOT NULL, truststore_version TEXT NOT NULL, truststore_pem BLOB NOT NULL, tags BLOB NOT NULL,
 PRIMARY KEY(partition,account_id,region,name)
);
CREATE TABLE apigatewayv2_mappings (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, domain_name TEXT NOT NULL, id TEXT NOT NULL,
 owner_stack_id TEXT NOT NULL, owner_logical_id TEXT NOT NULL, owner_token TEXT NOT NULL,
 api_id TEXT NOT NULL, stage TEXT NOT NULL, path TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,domain_name,id),
 UNIQUE(partition,account_id,region,domain_name,path),
 FOREIGN KEY(partition,account_id,region,domain_name) REFERENCES apigatewayv2_domains(partition,account_id,region,name) ON DELETE CASCADE
);
