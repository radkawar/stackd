-- Private native incarnation claims. Existing controls remain unclaimed;
-- public tags cannot confer ownership on an existing incarnation.
ALTER TABLE config_recorders ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE config_recorders ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE config_channels ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE config_channels ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE config_rules ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE config_rules ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE config_aggregators ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE config_aggregators ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE config_aggregation_authorizations ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE config_aggregation_authorizations ADD COLUMN cfn_token TEXT NOT NULL DEFAULT '';
ALTER TABLE config_recorders ADD COLUMN cfn_start_on_create BOOLEAN NOT NULL DEFAULT FALSE;
