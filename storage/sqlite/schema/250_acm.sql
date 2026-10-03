CREATE TABLE acm_certificates (
 arn TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 id TEXT NOT NULL UNIQUE,
 domain TEXT NOT NULL,
 status TEXT NOT NULL,
 type TEXT NOT NULL,
 key_algorithm TEXT NOT NULL,
 transparency TEXT NOT NULL,
 export_option TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 issued TIMESTAMP NOT NULL,
 imported TIMESTAMP NOT NULL,
 not_before TIMESTAMP NOT NULL,
 not_after TIMESTAMP NOT NULL,
 validation_deadline TIMESTAMP NOT NULL,
 next_check TIMESTAMP NOT NULL,
 renewal_updated TIMESTAMP NOT NULL,
 version INTEGER NOT NULL,
 material_version INTEGER NOT NULL,
 renewal_status TEXT NOT NULL,
 exported BOOLEAN NOT NULL,
 certificate_pem BLOB NOT NULL,
 chain_pem BLOB NOT NULL,
 private_key_pem BLOB NOT NULL
);
CREATE INDEX acm_certificates_scope ON acm_certificates(partition, account_id, region, arn);
CREATE INDEX acm_certificates_due ON acm_certificates(next_check, arn);
CREATE TABLE acm_validations (
 certificate_arn TEXT NOT NULL REFERENCES acm_certificates(arn) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 domain TEXT NOT NULL,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 status TEXT NOT NULL,
 PRIMARY KEY(certificate_arn, position)
);
CREATE TABLE acm_tags (
 certificate_arn TEXT NOT NULL REFERENCES acm_certificates(arn) ON DELETE CASCADE,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(certificate_arn, key)
);
CREATE TABLE acm_validation_tokens (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 domain TEXT NOT NULL,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(partition, account_id, domain)
);
CREATE TABLE acm_authority (
 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
 certificate_pem BLOB NOT NULL,
 private_key_pem BLOB NOT NULL
);
CREATE TABLE acm_request_receipts (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 token TEXT NOT NULL,
 arn TEXT NOT NULL,
 expires TIMESTAMP NOT NULL,
 PRIMARY KEY(partition, account_id, region, token)
);
