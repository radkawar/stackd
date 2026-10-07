ALTER TABLE athena_work_groups ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE athena_catalogs ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
