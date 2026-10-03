CREATE TABLE identitystore_stores (
 store_id TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 region TEXT NOT NULL
);
CREATE TABLE identitystore_users (
 store_id TEXT NOT NULL REFERENCES identitystore_stores(store_id) ON DELETE CASCADE,
 id TEXT NOT NULL,
 user_name TEXT NOT NULL,
 display_name TEXT NOT NULL,
 name_formatted TEXT NOT NULL,
 name_family TEXT NOT NULL,
 name_given TEXT NOT NULL,
 name_middle TEXT NOT NULL,
 name_prefix TEXT NOT NULL,
 name_suffix TEXT NOT NULL,
 nick_name TEXT NOT NULL,
 profile_url TEXT NOT NULL,
 title TEXT NOT NULL,
 user_type TEXT NOT NULL,
 preferred_language TEXT NOT NULL,
 locale TEXT NOT NULL,
 timezone TEXT NOT NULL,
 birthdate TEXT NOT NULL,
 website TEXT NOT NULL,
 PRIMARY KEY(store_id,id),
 UNIQUE(store_id,user_name)
);
CREATE TABLE identitystore_emails (
 store_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 value TEXT NOT NULL,
 type TEXT NOT NULL,
 is_primary INTEGER NOT NULL,
 PRIMARY KEY(store_id,user_id,ordinal),
 FOREIGN KEY(store_id,user_id) REFERENCES identitystore_users(store_id,id) ON DELETE CASCADE
);
CREATE TABLE identitystore_groups (
 store_id TEXT NOT NULL REFERENCES identitystore_stores(store_id) ON DELETE CASCADE,
 id TEXT NOT NULL,
 display_name TEXT NOT NULL,
 description TEXT NOT NULL,
 PRIMARY KEY(store_id,id),
 UNIQUE(store_id,display_name)
);
CREATE TABLE identitystore_memberships (
 store_id TEXT NOT NULL,
 id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 group_id TEXT NOT NULL,
 PRIMARY KEY(store_id,id),
 UNIQUE(store_id,user_id,group_id),
 FOREIGN KEY(store_id,user_id) REFERENCES identitystore_users(store_id,id) ON DELETE CASCADE,
 FOREIGN KEY(store_id,group_id) REFERENCES identitystore_groups(store_id,id) ON DELETE CASCADE
);
CREATE INDEX identitystore_memberships_group ON identitystore_memberships(store_id,group_id,id);
