-- Pending descriptions expose provisional timestamps without overwriting the
-- settled throughput history that survives billing-mode transitions.
ALTER TABLE dynamodb_pending_updates ADD COLUMN accepted_at TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00+00:00';
