ALTER TABLE iam_credential
    ADD COLUMN credential_request_parent_event_id TEXT NOT NULL DEFAULT '';
