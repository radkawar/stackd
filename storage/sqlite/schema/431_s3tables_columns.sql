-- Typed projection of the current accepted Iceberg schema, ordered by field.
CREATE TABLE s3tables_columns (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 table_arn TEXT NOT NULL, ordinal INTEGER NOT NULL,
 name TEXT NOT NULL, type TEXT NOT NULL, comment TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,table_arn,ordinal),
 FOREIGN KEY(table_arn) REFERENCES s3tables_tables(arn)
);
-- Metadata candidates become immutable before their bytes leave preparation.
-- Keep typed key ownership durable even when the candidate loses publication.
CREATE TABLE s3tables_metadata_files (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 table_arn TEXT NOT NULL, object_key TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,table_arn,object_key),
 FOREIGN KEY(table_arn) REFERENCES s3tables_tables(arn)
);
