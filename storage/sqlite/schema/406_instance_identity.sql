-- Existing databases predate retained bootstrap account selection. Preserve the
-- historical default; an explicit account-id override still selects its account.
CREATE TABLE instance_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    account_id TEXT NOT NULL CHECK (length(account_id) = 12 AND account_id NOT GLOB '*[^0-9]*')
);
INSERT INTO instance_identity (singleton, account_id) VALUES (1, '000000000000');
