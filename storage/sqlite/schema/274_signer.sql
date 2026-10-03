CREATE TABLE signer_authorities (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 certificate BLOB NOT NULL, private_key BLOB NOT NULL,
 PRIMARY KEY(partition,account_id,region)
);
CREATE TABLE signer_profiles (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 name TEXT NOT NULL, arn TEXT NOT NULL, version TEXT NOT NULL, version_arn TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL, is_current BOOLEAN NOT NULL,
 validity_value INTEGER NOT NULL, validity_type TEXT NOT NULL,
 created DATETIME NOT NULL, revoked_at DATETIME NOT NULL, effective_time DATETIME NOT NULL,
 revocation_reason TEXT NOT NULL, revoked_by TEXT NOT NULL,
 certificate BLOB NOT NULL, private_key BLOB NOT NULL,
 PRIMARY KEY(partition,account_id,region,name,version)
);
CREATE UNIQUE INDEX signer_current_profile ON signer_profiles(partition,account_id,region,name) WHERE is_current=1;
CREATE TABLE signer_profile_tags (
 version_arn TEXT NOT NULL REFERENCES signer_profiles(version_arn) ON DELETE CASCADE,
 tag_key TEXT NOT NULL, tag_value TEXT NOT NULL, PRIMARY KEY(version_arn,tag_key)
);
CREATE TABLE signer_jobs (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 id TEXT NOT NULL, arn TEXT NOT NULL UNIQUE,
 profile_name TEXT NOT NULL, profile_version TEXT NOT NULL, profile_version_arn TEXT NOT NULL,
 token TEXT NOT NULL, source_bucket TEXT NOT NULL, source_key TEXT NOT NULL, source_version TEXT NOT NULL,
 destination_bucket TEXT NOT NULL, destination_prefix TEXT NOT NULL, destination_key TEXT NOT NULL,
 status TEXT NOT NULL, status_reason TEXT NOT NULL, requested_by TEXT NOT NULL,
 created DATETIME NOT NULL, completed DATETIME NOT NULL, expires DATETIME NOT NULL, revoked_at DATETIME NOT NULL,
 revocation_reason TEXT NOT NULL, revoked_by TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,id), UNIQUE(partition,account_id,region,token),
 FOREIGN KEY(profile_version_arn) REFERENCES signer_profiles(version_arn)
);
CREATE TABLE signer_job_certificates (
 job_arn TEXT NOT NULL REFERENCES signer_jobs(arn) ON DELETE CASCADE,
 position INTEGER NOT NULL, certificate_hash TEXT NOT NULL,
 PRIMARY KEY(job_arn,position)
);
