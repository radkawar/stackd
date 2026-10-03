ALTER TABLE api_call_events ADD COLUMN identity_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE api_call_events ADD COLUMN shared_event_id TEXT NOT NULL DEFAULT '';
ALTER TABLE api_call_events ADD COLUMN api_version TEXT NOT NULL DEFAULT '';
