-- Private CloudFormation provenance of a parameter incarnation. Public tags
-- never carry ownership; empty is the direct-API scope, and existing rows are
-- never adopted from their tags.
ALTER TABLE ssm_parameters ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
