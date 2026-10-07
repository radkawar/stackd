ALTER TABLE appsync_apis ADD COLUMN schema_ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE appsync_data_sources ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE appsync_functions ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE appsync_resolvers ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
ALTER TABLE appsync_keys ADD COLUMN ownership TEXT NOT NULL DEFAULT '';
