-- Private statement receipts are deliberately separate from public policy JSON.
-- Existing policies remain unowned; migration never adopts native statements.
CREATE TABLE lambda_layer_permission_owners (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, layer_name TEXT NOT NULL,
 version INTEGER NOT NULL, statement_id TEXT NOT NULL CHECK(statement_id <> ''),
 owner_stack_id TEXT NOT NULL CHECK(owner_stack_id <> ''),
 owner_logical_id TEXT NOT NULL CHECK(owner_logical_id <> ''),
 owner_token TEXT NOT NULL CHECK(owner_token <> ''),
 PRIMARY KEY(partition,account,region,layer_name,version,statement_id),
 FOREIGN KEY(partition,account,region,layer_name,version) REFERENCES lambda_layer_policies(partition,account,region,layer_name,version) ON DELETE CASCADE
);
