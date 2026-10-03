-- name: GetZone :one
SELECT * FROM route53_zones WHERE id=?;
-- name: ListZones :many
SELECT * FROM route53_zones ORDER BY id;
-- name: PutZone :exec
INSERT INTO route53_zones(id,partition,account_id,name,caller_reference,comment,created) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET comment=excluded.comment;
-- name: DeleteZone :exec
DELETE FROM route53_zones WHERE id=?;
-- name: ListRecordSets :many
SELECT * FROM route53_record_sets WHERE zone_id=? ORDER BY name,type,identifier;
-- name: ListRecordValues :many
SELECT * FROM route53_record_values WHERE zone_id=? ORDER BY name,type,identifier,position;
-- name: DeleteRecordSets :exec
DELETE FROM route53_record_sets WHERE zone_id=?;
-- name: PutRecordSet :exec
INSERT INTO route53_record_sets(zone_id,name,type,identifier,ttl,weighted,weight,multi_value,alias_zone_id,alias_dns_name) VALUES(?,?,?,?,?,?,?,?,?,?);
-- name: PutRecordValue :exec
INSERT INTO route53_record_values(zone_id,name,type,identifier,position,value) VALUES(?,?,?,?,?,?);
-- name: GetChange :one
SELECT * FROM route53_changes WHERE id=?;
-- name: PutChange :exec
INSERT INTO route53_changes(id,partition,account_id,zone_id,comment,submitted,ready) VALUES(?,?,?,?,?,?,?);
