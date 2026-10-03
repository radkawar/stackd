-- Application configuration documents share the existing immutable content owner.
-- Requires is exactly one pinned schema version, fenced by document incarnation;
-- it survives force-deletion of the schema, so it is not a cascading foreign key.
ALTER TABLE ssm_documents ADD COLUMN document_type TEXT NOT NULL DEFAULT 'Command';
ALTER TABLE ssm_documents ADD COLUMN schema_name TEXT NOT NULL DEFAULT '';
ALTER TABLE ssm_documents ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ssm_documents ADD COLUMN schema_document_uuid TEXT NOT NULL DEFAULT '';
