-- The accepted deployment, not a separate replay ledger, owns its producer.
ALTER TABLE appconfig_deployments ADD COLUMN pipeline_action_id TEXT NOT NULL DEFAULT '';
