CREATE TABLE route53_zones (
 id TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 name TEXT NOT NULL,
 caller_reference TEXT NOT NULL,
 comment TEXT NOT NULL,
 created TIMESTAMP NOT NULL,
 UNIQUE (partition,account_id,caller_reference)
);
CREATE TABLE route53_record_sets (
 zone_id TEXT NOT NULL REFERENCES route53_zones(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 type TEXT NOT NULL,
 identifier TEXT NOT NULL,
 ttl INTEGER NOT NULL,
 weighted BOOLEAN NOT NULL,
 weight INTEGER NOT NULL,
 multi_value BOOLEAN NOT NULL,
 alias_zone_id TEXT NOT NULL,
 alias_dns_name TEXT NOT NULL,
 PRIMARY KEY(zone_id,name,type,identifier)
);
CREATE TABLE route53_record_values (
 zone_id TEXT NOT NULL,
 name TEXT NOT NULL,
 type TEXT NOT NULL,
 identifier TEXT NOT NULL,
 position INTEGER NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(zone_id,name,type,identifier,position),
 FOREIGN KEY(zone_id,name,type,identifier) REFERENCES route53_record_sets(zone_id,name,type,identifier) ON DELETE CASCADE
);
-- Change receipts survive zone deletion and are scoped independently.
CREATE TABLE route53_changes (
 id TEXT PRIMARY KEY,
 partition TEXT NOT NULL,
 account_id TEXT NOT NULL,
 zone_id TEXT NOT NULL,
 comment TEXT NOT NULL,
 submitted TIMESTAMP NOT NULL,
 ready TIMESTAMP NOT NULL
);
