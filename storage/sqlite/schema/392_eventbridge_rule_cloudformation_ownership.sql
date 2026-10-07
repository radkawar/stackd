-- Private controller provenance for native rules. Legacy public marker tags
-- are customer metadata and are deliberately not backfilled.
ALTER TABLE eventbridge_rules ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
