-- User-defined tags belong to the exact scoped bucket/table incarnation.
CREATE TABLE s3tables_tags (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 resource_arn TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,resource_arn,key)
);
CREATE TRIGGER s3tables_bucket_tags_delete AFTER DELETE ON s3tables_buckets
BEGIN
 DELETE FROM s3tables_tags WHERE partition=OLD.partition AND account_id=OLD.account_id AND region=OLD.region AND resource_arn=OLD.arn;
END;
CREATE TRIGGER s3tables_table_tags_delete AFTER UPDATE OF deleted ON s3tables_tables WHEN NEW.deleted=1
BEGIN
 DELETE FROM s3tables_tags WHERE partition=NEW.partition AND account_id=NEW.account_id AND region=NEW.region AND resource_arn=NEW.arn;
END;
