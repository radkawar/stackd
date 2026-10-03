ALTER TABLE eventbridge_buses ADD COLUMN policy TEXT NOT NULL DEFAULT '';

CREATE TABLE eventbridge_bus_policy_principals (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, bus_name TEXT NOT NULL,
    arn TEXT NOT NULL, principal_id TEXT NOT NULL,
    PRIMARY KEY (partition, account, region, bus_name, arn),
    FOREIGN KEY (partition, account, region, bus_name)
        REFERENCES eventbridge_buses(partition, account, region, name) ON DELETE CASCADE
);
