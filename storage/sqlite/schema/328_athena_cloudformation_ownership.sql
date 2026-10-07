ALTER TABLE athena_named_queries ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE athena_prepared_statements ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
