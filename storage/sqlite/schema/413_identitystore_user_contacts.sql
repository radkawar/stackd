CREATE TABLE identitystore_addresses (
 store_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 country TEXT NOT NULL,
 formatted TEXT NOT NULL,
 locality TEXT NOT NULL,
 postal_code TEXT NOT NULL,
 region TEXT NOT NULL,
 street_address TEXT NOT NULL,
 type TEXT NOT NULL,
 is_primary INTEGER NOT NULL CHECK(is_primary IN (0,1)),
 PRIMARY KEY(store_id,user_id,ordinal),
 FOREIGN KEY(store_id,user_id) REFERENCES identitystore_users(store_id,id) ON DELETE CASCADE
);
CREATE TABLE identitystore_phone_numbers (
 store_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 value TEXT NOT NULL,
 type TEXT NOT NULL,
 is_primary INTEGER NOT NULL CHECK(is_primary IN (0,1)),
 PRIMARY KEY(store_id,user_id,ordinal),
 FOREIGN KEY(store_id,user_id) REFERENCES identitystore_users(store_id,id) ON DELETE CASCADE
);
