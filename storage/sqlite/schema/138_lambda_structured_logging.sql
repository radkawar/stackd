ALTER TABLE lambda_functions ADD COLUMN log_format TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_functions ADD COLUMN application_log_level TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_functions ADD COLUMN system_log_level TEXT NOT NULL DEFAULT '';
