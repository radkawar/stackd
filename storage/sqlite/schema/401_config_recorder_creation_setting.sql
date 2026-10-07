-- Keep declarative creation configuration separate from the consumed start intent.
-- Historical rows remain unknown; never infer this setting from mutable public tags.
ALTER TABLE config_recorders ADD COLUMN cfn_started_on_create BOOLEAN;
