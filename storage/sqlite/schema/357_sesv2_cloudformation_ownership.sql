-- Identity/configuration-set claims are private native incarnation authority.
ALTER TABLE sesv2_identities ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE sesv2_configuration_sets ADD COLUMN cfn_owner TEXT NOT NULL DEFAULT '';
