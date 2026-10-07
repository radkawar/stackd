-- Private CloudFormation provenance for buckets, bucket-policy edges and access
-- points. Public tags never carry ownership; empty is the direct-API scope, and
-- existing rows are never adopted from their tags.
ALTER TABLE s3_buckets ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_buckets ADD COLUMN policy_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE s3_access_points ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
