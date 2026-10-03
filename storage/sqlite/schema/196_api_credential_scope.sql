ALTER TABLE api_call_events ADD COLUMN issuer_type TEXT NOT NULL DEFAULT '';
ALTER TABLE api_call_events ADD COLUMN credentials_issued_to TEXT NOT NULL DEFAULT '';
