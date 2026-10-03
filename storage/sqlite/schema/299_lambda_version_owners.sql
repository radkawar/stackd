-- Receipts are private publication identities, not public tags. Legacy versions
-- remain unowned; a receipt is created only by a trusted publication request.
CREATE TABLE lambda_version_owners (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false),
 version INTEGER NOT NULL CHECK(version > 0 AND version < 9223372036854775807),
 owner_stack_id TEXT NOT NULL CHECK(owner_stack_id <> ''),
 owner_logical_id TEXT NOT NULL CHECK(owner_logical_id <> ''),
 owner_token TEXT NOT NULL CHECK(owner_token <> ''),
 PRIMARY KEY(partition,account,region,function_name,owner_stack_id,owner_logical_id,owner_token),
 UNIQUE(partition,account,region,function_name,version),
 FOREIGN KEY(partition,account,region,function_name,pending,version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
