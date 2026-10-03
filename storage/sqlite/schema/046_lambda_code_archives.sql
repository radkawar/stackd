CREATE TABLE lambda_code_archives (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
    code_sha256 TEXT NOT NULL, code BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL, retain_until TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, region, code_sha256)
);
CREATE INDEX lambda_code_archives_retention ON lambda_code_archives(retain_until);

-- SQLite selects the code from the row with the earliest modification time.
-- Identical scoped digests share immutable bytes across both deployment slots.
INSERT INTO lambda_code_archives(partition,account,region,code_sha256,code,created_at,retain_until)
SELECT partition,account,region,code_sha256,code,MIN(modified),MIN(modified)
FROM lambda_functions GROUP BY partition,account,region,code_sha256;

ALTER TABLE lambda_functions ADD COLUMN code_size INTEGER NOT NULL DEFAULT 0;
UPDATE lambda_functions SET code_size=length(code);
ALTER TABLE lambda_functions DROP COLUMN code;
CREATE INDEX lambda_functions_code_archive ON lambda_functions(partition,account,region,code_sha256);

CREATE TABLE lambda_code_signing_keys (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
    access_key_id TEXT NOT NULL, secret_access_key TEXT NOT NULL,
    PRIMARY KEY (partition, account, region)
);
