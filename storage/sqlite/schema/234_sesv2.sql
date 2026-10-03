CREATE TABLE sesv2_identities (
 arn TEXT PRIMARY KEY, partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 verified INTEGER NOT NULL, verification_token TEXT NOT NULL, verification_expires INTEGER NOT NULL, configuration_set TEXT NOT NULL,
 UNIQUE(partition, account_id, region, name)
);
CREATE UNIQUE INDEX sesv2_identity_token ON sesv2_identities(verification_token) WHERE verification_token <> '';
CREATE TABLE sesv2_identity_tags (arn TEXT NOT NULL REFERENCES sesv2_identities(arn) ON DELETE CASCADE, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(arn,key));
CREATE TABLE sesv2_templates (
 arn TEXT PRIMARY KEY, partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 subject TEXT NOT NULL, text_body TEXT NOT NULL, html_body TEXT NOT NULL, created INTEGER NOT NULL,
 UNIQUE(partition,account_id,region,name)
);
CREATE TABLE sesv2_configuration_sets (
 arn TEXT PRIMARY KEY, partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL, sending_enabled INTEGER NOT NULL,
 UNIQUE(partition,account_id,region,name)
);
CREATE TABLE sesv2_configuration_tags (arn TEXT NOT NULL REFERENCES sesv2_configuration_sets(arn) ON DELETE CASCADE, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(arn,key));
CREATE TABLE sesv2_accounts (partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, sending_enabled INTEGER NOT NULL, PRIMARY KEY(partition,account_id,region));
CREATE TABLE sesv2_messages (
 arn TEXT PRIMARY KEY, partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, id TEXT NOT NULL,
 sender TEXT NOT NULL, feedback TEXT NOT NULL, subject TEXT NOT NULL, text_body TEXT NOT NULL, html_body TEXT NOT NULL,
 content_kind TEXT NOT NULL, template_name TEXT NOT NULL, template_data TEXT NOT NULL, configuration_set TEXT NOT NULL,
 mime BLOB NOT NULL, accepted INTEGER NOT NULL, due INTEGER NOT NULL, capture_pending INTEGER NOT NULL, capture_error TEXT NOT NULL,
 UNIQUE(partition,account_id,region,id)
);
CREATE TABLE sesv2_message_addresses (arn TEXT NOT NULL REFERENCES sesv2_messages(arn) ON DELETE CASCADE, kind TEXT NOT NULL, position INTEGER NOT NULL, address TEXT NOT NULL, PRIMARY KEY(arn,kind,position));
CREATE TABLE sesv2_message_tags (arn TEXT NOT NULL REFERENCES sesv2_messages(arn) ON DELETE CASCADE, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(arn,key));
CREATE INDEX sesv2_pending_capture ON sesv2_messages(due,arn) WHERE capture_pending=1;
