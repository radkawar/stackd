-- Owner creation identity is independent of mutable timestamps and parameter versions.
ALTER TABLE s3_buckets ADD COLUMN incarnation TEXT NOT NULL DEFAULT '';
ALTER TABLE ssm_parameters ADD COLUMN incarnation TEXT NOT NULL DEFAULT '';

-- Existing live owners acquire one durable random identity at migration, never at read.
UPDATE s3_buckets SET incarnation = lower(hex(randomblob(16)));
UPDATE ssm_parameters SET incarnation = lower(hex(randomblob(16)));
