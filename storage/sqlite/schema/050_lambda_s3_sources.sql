-- Absence denotes COPY storage, including every deployment predating this table.
-- Resolved S3 identity belongs to the exact current, pending or published snapshot.
CREATE TABLE lambda_function_s3_sources (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL, version INTEGER NOT NULL,
 reference_bucket TEXT NOT NULL, reference_key TEXT NOT NULL, reference_version_id TEXT NOT NULL,
 code_source_check_at TIMESTAMP NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,pending,version),
 FOREIGN KEY(partition,account,region,function_name,pending,version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
CREATE INDEX lambda_function_s3_sources_due ON lambda_function_s3_sources(code_source_check_at) WHERE pending=false;
