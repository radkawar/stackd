-- Retain accepted command identity for recovered provisioning transitions.
-- Preexisting jobs have no captured origin; do not synthesize historical data.
ALTER TABLE org_creations ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE org_creations ADD COLUMN request_region TEXT NOT NULL DEFAULT '';
ALTER TABLE org_creations ADD COLUMN actor_arn TEXT NOT NULL DEFAULT '';
