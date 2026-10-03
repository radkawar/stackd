CREATE TABLE lambda_function_policies (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    pending BOOLEAN NOT NULL DEFAULT false CHECK (pending = false),
    document TEXT NOT NULL, revision TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, function_name),
    FOREIGN KEY (partition, account, region, function_name, pending) REFERENCES lambda_functions(partition, account, region, name, pending) ON DELETE CASCADE
);
CREATE TABLE lambda_function_policy_principals (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    principal TEXT NOT NULL, principal_id TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, function_name, principal),
    FOREIGN KEY (partition, account, region, function_name) REFERENCES lambda_function_policies(partition, account, region, function_name) ON DELETE CASCADE
);
