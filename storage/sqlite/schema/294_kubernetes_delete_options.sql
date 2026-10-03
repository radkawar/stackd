-- Historical Metadata audit cannot establish whether a body overrode the URI.
ALTER TABLE kubernetes_audit_events ADD COLUMN delete_options_observed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE kubernetes_audit_events ADD COLUMN dry_run BOOLEAN NOT NULL DEFAULT FALSE;
