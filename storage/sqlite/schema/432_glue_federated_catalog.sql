ALTER TABLE glue_catalogs ADD COLUMN federation_identifier TEXT;
ALTER TABLE glue_catalogs ADD COLUMN federation_connection_name TEXT;
ALTER TABLE glue_catalogs ADD COLUMN federation_connection_type TEXT;
