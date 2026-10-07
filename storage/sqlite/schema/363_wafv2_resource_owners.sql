-- Private native claims are not derived from existing customer tags.
ALTER TABLE wafv2_web_acls ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE wafv2_web_acls ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE wafv2_web_acls ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
ALTER TABLE wafv2_ip_sets ADD COLUMN owner_stack_id TEXT NOT NULL DEFAULT '';
ALTER TABLE wafv2_ip_sets ADD COLUMN owner_logical_id TEXT NOT NULL DEFAULT '';
ALTER TABLE wafv2_ip_sets ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';
