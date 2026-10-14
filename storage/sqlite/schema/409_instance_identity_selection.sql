-- Existing retained selections are final. Fresh bootstrap initialization and
-- pre-selection legacy upgrades explicitly open their first selection in Open.
ALTER TABLE instance_identity ADD COLUMN selected BOOLEAN NOT NULL DEFAULT TRUE;
