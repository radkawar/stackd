-- Private CloudFormation provenance of a document. Replacement carries it to
-- the replacing incarnation; public tags never carry ownership, and existing
-- rows are never adopted from their tags.
ALTER TABLE ssm_documents ADD COLUMN cloudformation_owner TEXT NOT NULL DEFAULT '';
