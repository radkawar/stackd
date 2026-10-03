CREATE TABLE dynamodb_transaction_capacities (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 token TEXT NOT NULL, expires_at TIMESTAMP NOT NULL,
 return_consumed_capacity TEXT NOT NULL, return_item_collection_metrics TEXT NOT NULL,
 canceled_request TEXT NOT NULL,
 PRIMARY KEY(partition, account_id, region, token)
);
CREATE INDEX dynamodb_transaction_capacities_expiry ON dynamodb_transaction_capacities(expires_at);

CREATE TABLE dynamodb_transaction_capacity_reads (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 token TEXT NOT NULL, position INTEGER NOT NULL,
 table_name TEXT NOT NULL, units REAL NOT NULL,
 PRIMARY KEY(partition, account_id, region, token, position),
 FOREIGN KEY(partition, account_id, region, token)
 REFERENCES dynamodb_transaction_capacities(partition, account_id, region, token) ON DELETE CASCADE
);
