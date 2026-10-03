CREATE TABLE lambda_functions (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
    pending BOOLEAN NOT NULL,
    runtime TEXT NOT NULL, handler TEXT NOT NULL, role TEXT NOT NULL, description TEXT NOT NULL, architecture TEXT NOT NULL,
    code BLOB NOT NULL, code_sha256 TEXT NOT NULL,
    timeout INTEGER NOT NULL, memory_mb INTEGER NOT NULL, ephemeral_mb INTEGER NOT NULL,
    revision TEXT NOT NULL, modified TIMESTAMP NOT NULL,
    state TEXT NOT NULL, state_reason TEXT NOT NULL, state_reason_code TEXT NOT NULL,
    update_status TEXT NOT NULL, update_reason TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, name, pending)
);
CREATE TABLE lambda_function_variables (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    pending BOOLEAN NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, function_name, pending, key),
    FOREIGN KEY (partition, account, region, function_name, pending) REFERENCES lambda_functions(partition, account, region, name, pending) ON DELETE CASCADE
);
CREATE TABLE lambda_function_tags (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    pending BOOLEAN NOT NULL,
    key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, function_name, pending, key),
    FOREIGN KEY (partition, account, region, function_name, pending) REFERENCES lambda_functions(partition, account, region, name, pending) ON DELETE CASCADE
);
