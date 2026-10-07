CREATE TABLE wafv2_web_acls (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 arn TEXT NOT NULL, name TEXT NOT NULL, id TEXT NOT NULL, description TEXT NOT NULL,
 lock_token TEXT NOT NULL, definition BLOB NOT NULL, capacity INTEGER NOT NULL,
 created DATETIME NOT NULL, updated DATETIME NOT NULL,
 PRIMARY KEY(partition,account_id,region,arn),
 UNIQUE(partition,account_id,region,name)
);
CREATE TABLE wafv2_web_acl_tags (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, arn TEXT NOT NULL,
 tag_key TEXT NOT NULL, tag_value TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,arn,tag_key),
 FOREIGN KEY(partition,account_id,region,arn) REFERENCES wafv2_web_acls(partition,account_id,region,arn) ON DELETE CASCADE
);
CREATE TABLE wafv2_ip_sets (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 arn TEXT NOT NULL, name TEXT NOT NULL, id TEXT NOT NULL, description TEXT NOT NULL,
 lock_token TEXT NOT NULL, ip_address_version TEXT NOT NULL, addresses BLOB NOT NULL,
 created DATETIME NOT NULL, updated DATETIME NOT NULL,
 PRIMARY KEY(partition,account_id,region,arn),
 UNIQUE(partition,account_id,region,name)
);
CREATE TABLE wafv2_ip_set_tags (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL, arn TEXT NOT NULL,
 tag_key TEXT NOT NULL, tag_value TEXT NOT NULL,
 PRIMARY KEY(partition,account_id,region,arn,tag_key),
 FOREIGN KEY(partition,account_id,region,arn) REFERENCES wafv2_ip_sets(partition,account_id,region,arn) ON DELETE CASCADE
);
-- Associations reference live web ACLs; DeleteWebACL removes stale rows first.
CREATE TABLE wafv2_associations (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 resource_arn TEXT NOT NULL, web_acl_arn TEXT NOT NULL,
 resource_incarnation TEXT NOT NULL,
 owner_stack_id TEXT NOT NULL, owner_logical_id TEXT NOT NULL, owner_token TEXT NOT NULL,
 created DATETIME NOT NULL,
 PRIMARY KEY(partition,account_id,region,resource_arn),
 FOREIGN KEY(partition,account_id,region,web_acl_arn) REFERENCES wafv2_web_acls(partition,account_id,region,arn)
);
CREATE INDEX wafv2_associations_web_acl ON wafv2_associations(partition,account_id,region,web_acl_arn);
-- Pending AWS/WAFV2 observations survive web ACL deletion until published.
CREATE TABLE wafv2_metric_samples (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 web_acl TEXT NOT NULL, rule TEXT NOT NULL, minute DATETIME NOT NULL,
 metric_name TEXT NOT NULL, count INTEGER NOT NULL,
 PRIMARY KEY(partition,account_id,region,web_acl,rule,minute,metric_name)
);
CREATE INDEX wafv2_metric_samples_due ON wafv2_metric_samples(minute,partition,account_id,region,web_acl,rule);
CREATE TABLE wafv2_sampled_requests (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 web_acl_arn TEXT NOT NULL, metric_name TEXT NOT NULL, at DATETIME NOT NULL, sequence INTEGER NOT NULL,
 sample BLOB NOT NULL,
 PRIMARY KEY(partition,account_id,region,web_acl_arn,metric_name,at,sequence)
);
CREATE INDEX wafv2_sampled_requests_at ON wafv2_sampled_requests(at);
CREATE TABLE wafv2_sample_population (
 partition TEXT NOT NULL, account_id TEXT NOT NULL, region TEXT NOT NULL,
 web_acl_arn TEXT NOT NULL, metric_name TEXT NOT NULL, minute DATETIME NOT NULL, population INTEGER NOT NULL,
 PRIMARY KEY(partition,account_id,region,web_acl_arn,metric_name,minute)
);
CREATE INDEX wafv2_sample_population_minute ON wafv2_sample_population(minute);
