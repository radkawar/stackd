-- Existing subscriptions and sealed deliveries continue to use text after upgrade.
ALTER TABLE ec2_flow_logs ADD COLUMN file_format TEXT NOT NULL DEFAULT 'plain-text' CHECK (file_format IN ('plain-text', 'parquet'));
ALTER TABLE ec2_flow_log_deliveries ADD COLUMN file_format TEXT NOT NULL DEFAULT 'plain-text' CHECK (file_format IN ('plain-text', 'parquet'));
