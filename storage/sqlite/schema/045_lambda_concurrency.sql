ALTER TABLE lambda_functions ADD COLUMN deployment_revision TEXT NOT NULL DEFAULT '';
UPDATE lambda_functions SET deployment_revision = revision;

CREATE TABLE lambda_function_concurrency (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
    pending BOOLEAN NOT NULL DEFAULT false CHECK (pending = false),
    reserved_concurrency INTEGER NOT NULL,
    PRIMARY KEY (partition, account, region, function_name),
    FOREIGN KEY (partition, account, region, function_name, pending) REFERENCES lambda_functions(partition, account, region, name, pending) ON DELETE CASCADE
);

DROP INDEX lambda_invocations_in_flight;
