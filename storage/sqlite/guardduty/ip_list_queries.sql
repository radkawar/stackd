-- name: PutIPList :exec
INSERT INTO guardduty_ip_lists (partition, account_id, region, detector_id, kind, id, arn, name, format, location, expected_bucket_owner, client_token, status, version, due, tags_present)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, detector_id, kind, id) DO UPDATE SET arn=excluded.arn, name=excluded.name, format=excluded.format, location=excluded.location, expected_bucket_owner=excluded.expected_bucket_owner, client_token=excluded.client_token, status=excluded.status, version=excluded.version, due=excluded.due, tags_present=excluded.tags_present;

-- name: GetIPList :one
SELECT * FROM guardduty_ip_lists WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND kind=? AND id=?;

-- name: ListIPLists :many
SELECT * FROM guardduty_ip_lists WHERE partition=? AND account_id=? AND region=? AND detector_id=? ORDER BY kind, id;

-- name: MatchingIPLists :many
SELECT l.* FROM guardduty_ip_lists AS l
WHERE l.partition=? AND l.account_id=? AND l.region=? AND l.detector_id=? AND l.status='ACTIVE'
AND (SELECT r.last_ip FROM guardduty_ip_ranges AS r
     WHERE r.partition=l.partition AND r.account_id=l.account_id AND r.region=l.region
       AND r.detector_id=l.detector_id AND r.kind=l.kind AND r.id=l.id
       AND r.first_ip <= sqlc.arg(ip)
     ORDER BY r.first_ip DESC LIMIT 1) >= sqlc.arg(ip)
ORDER BY l.kind, l.id;

-- name: DeleteIPList :exec
DELETE FROM guardduty_ip_lists WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND kind=? AND id=?;

-- name: ListIPListTags :many
SELECT * FROM guardduty_ip_list_tags WHERE arn=? ORDER BY tag_key;

-- name: DeleteIPListTags :exec
DELETE FROM guardduty_ip_list_tags WHERE arn=?;

-- name: PutIPListTag :exec
INSERT INTO guardduty_ip_list_tags (arn, tag_key, tag_value) VALUES (?, ?, ?);

-- name: DeleteIPRanges :exec
DELETE FROM guardduty_ip_ranges WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND kind=? AND id=?;

-- name: PutIPRange :exec
INSERT INTO guardduty_ip_ranges (partition, account_id, region, detector_id, kind, id, first_ip, last_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
