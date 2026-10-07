-- Private statement incarnation rows; public tags are deliberately not backfilled.
CREATE TABLE eventbridge_bus_policy_statement_owners (
    partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, bus_name TEXT NOT NULL,
    statement_id TEXT NOT NULL, cfn_owner TEXT NOT NULL CHECK (cfn_owner <> ''),
    PRIMARY KEY (partition, account, region, bus_name, statement_id),
    FOREIGN KEY (partition, account, region, bus_name) REFERENCES eventbridge_buses(partition, account, region, name) ON DELETE CASCADE
);
