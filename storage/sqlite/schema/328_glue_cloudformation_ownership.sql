ALTER TABLE glue_tables ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE glue_partitions ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE glue_classifiers ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE glue_security_configuration ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE glue_schema_versions ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE glue_schema_metadata ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE glue_connection_encryption ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
