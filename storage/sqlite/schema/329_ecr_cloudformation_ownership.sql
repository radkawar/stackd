ALTER TABLE ecr_registries ADD COLUMN policy_ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE ecr_registries ADD COLUMN replication_ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE ecr_registries ADD COLUMN scanning_ownership TEXT NOT NULL DEFAULT '';
