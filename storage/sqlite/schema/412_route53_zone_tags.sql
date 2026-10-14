CREATE TABLE route53_zone_tags (
 zone_id TEXT NOT NULL REFERENCES route53_zones(id) ON DELETE CASCADE,
 key TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(zone_id,key)
);
