CREATE TABLE dynamodb_on_demand_switches (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 name TEXT NOT NULL,
 position INTEGER NOT NULL,
 switched_at TIMESTAMP NOT NULL,
 PRIMARY KEY (partition, account_id, region, name, position),
 FOREIGN KEY (partition, account_id, region, name) REFERENCES dynamodb_tables(partition, account_id, region, name) ON DELETE CASCADE
);
