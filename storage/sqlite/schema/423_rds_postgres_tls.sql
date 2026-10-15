-- Only public trust material is retained here; native runtimes own private keys.
-- Legacy empty trust must reconcile through the native owner before SQL use.
ALTER TABLE rds_database ADD COLUMN ca BLOB NOT NULL DEFAULT X'';
