CREATE TABLE cognitoidp_email_codes (
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 pool_id TEXT NOT NULL,
 username TEXT NOT NULL,
 kind TEXT NOT NULL,
 expires TIMESTAMP NOT NULL,
 digest BLOB NOT NULL,
 PRIMARY KEY (partition,account_id,region,pool_id,username,kind),
 FOREIGN KEY (partition,account_id,region,pool_id,username) REFERENCES cognitoidp_users(partition,account_id,region,pool_id,username) ON DELETE CASCADE
);
