ALTER TABLE kubernetes_audit_events ADD COLUMN role_ref_api_group TEXT NOT NULL DEFAULT '';
ALTER TABLE kubernetes_audit_events ADD COLUMN role_ref_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE kubernetes_audit_events ADD COLUMN role_ref_name TEXT NOT NULL DEFAULT '';
CREATE TABLE kubernetes_audit_subjects (
 sequence INTEGER NOT NULL REFERENCES kubernetes_audit_events(sequence) ON DELETE CASCADE,
 position INTEGER NOT NULL,
 api_group TEXT NOT NULL,
 kind TEXT NOT NULL,
 name TEXT NOT NULL,
 namespace TEXT NOT NULL,
 PRIMARY KEY(sequence,position)
) WITHOUT ROWID;
