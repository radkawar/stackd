-- name: PutDetector :exec
INSERT INTO guardduty_detectors (partition, account_id, region, id, arn, status, frequency, service_role, client_token, created, updated, features_present, tags_present) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, id) DO UPDATE SET arn=excluded.arn, status=excluded.status, frequency=excluded.frequency, service_role=excluded.service_role, client_token=excluded.client_token, created=excluded.created, updated=excluded.updated, features_present=excluded.features_present, tags_present=excluded.tags_present;

-- name: GetDetector :one
SELECT * FROM guardduty_detectors WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: DeleteDetector :exec
DELETE FROM guardduty_detectors WHERE partition=? AND account_id=? AND region=? AND id=?;

-- name: AllDetectors :many
SELECT * FROM guardduty_detectors ORDER BY arn;

-- name: PutFinding :exec
INSERT INTO guardduty_findings (partition, account_id, region, detector_id, id, sample_type, sample_revision, created, updated, count, archived, feedback, last_published, publish_due, suppressed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, detector_id, id) DO UPDATE SET sample_type=excluded.sample_type, sample_revision=excluded.sample_revision, created=excluded.created, updated=excluded.updated, count=excluded.count, archived=excluded.archived, feedback=excluded.feedback, last_published=excluded.last_published, publish_due=excluded.publish_due, suppressed=excluded.suppressed;

-- name: GetFinding :one
SELECT * FROM guardduty_findings WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=?;

-- name: DeleteFinding :exec
DELETE FROM guardduty_findings WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=?;

-- name: ListFindings :many
SELECT * FROM guardduty_findings WHERE partition=? AND account_id=? AND region=? AND detector_id=? ORDER BY id;

-- name: PutObservation :exec
INSERT INTO guardduty_observations (partition, account_id, region, detector_id, id, type, title, description, severity, event_id, access_key_id, principal_id, user_name, user_type, api, service_name, source_ip, error_code, resource_type, resource_name, resource_arn, feature_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, detector_id, id) DO UPDATE SET type=excluded.type, title=excluded.title, description=excluded.description, severity=excluded.severity, event_id=excluded.event_id, access_key_id=excluded.access_key_id, principal_id=excluded.principal_id, user_name=excluded.user_name, user_type=excluded.user_type, api=excluded.api, service_name=excluded.service_name, source_ip=excluded.source_ip, error_code=excluded.error_code, resource_type=excluded.resource_type, resource_name=excluded.resource_name, resource_arn=excluded.resource_arn, feature_name=excluded.feature_name;

-- name: GetObservation :one
SELECT * FROM guardduty_observations WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=?;

-- name: ListObservations :many
SELECT * FROM guardduty_observations WHERE partition=? AND account_id=? AND region=? AND detector_id=? ORDER BY id;

-- name: DeleteObservation :exec
DELETE FROM guardduty_observations WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=?;

-- name: PutObservationThreatList :exec
INSERT INTO guardduty_observation_threat_lists (partition, account_id, region, detector_id, id, position, name) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetObservationThreatLists :many
SELECT name FROM guardduty_observation_threat_lists WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=? ORDER BY position;

-- name: ListObservationThreatLists :many
SELECT id, name FROM guardduty_observation_threat_lists WHERE partition=? AND account_id=? AND region=? AND detector_id=? ORDER BY id, position;

-- name: DeleteObservationThreatLists :exec
DELETE FROM guardduty_observation_threat_lists WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND id=?;

-- name: PutFilter :exec
INSERT INTO guardduty_filters (partition, account_id, region, detector_id, name, arn, action, description, client_token, description_set, rank, version, created, updated, criteria_present, tags_present) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(partition, account_id, region, detector_id, name) DO UPDATE SET arn=excluded.arn, action=excluded.action, description=excluded.description, client_token=excluded.client_token, description_set=excluded.description_set, rank=excluded.rank, version=excluded.version, created=excluded.created, updated=excluded.updated, criteria_present=excluded.criteria_present, tags_present=excluded.tags_present;

-- name: GetFilter :one
SELECT * FROM guardduty_filters WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND name=?;

-- name: DeleteFilter :exec
DELETE FROM guardduty_filters WHERE partition=? AND account_id=? AND region=? AND detector_id=? AND name=?;

-- name: ListFilters :many
SELECT * FROM guardduty_filters WHERE partition=? AND account_id=? AND region=? AND detector_id=? ORDER BY name;

-- name: PutDetectorTag :exec
INSERT INTO guardduty_detector_tags (arn, tag_key, tag_value) VALUES (?, ?, ?)
ON CONFLICT(arn, tag_key) DO UPDATE SET tag_value=excluded.tag_value;

-- name: ListDetectorTags :many
SELECT * FROM guardduty_detector_tags WHERE arn=? ORDER BY tag_key;

-- name: DeleteDetectorTags :exec
DELETE FROM guardduty_detector_tags WHERE arn=?;

-- name: PutFeature :exec
INSERT INTO guardduty_features (arn, position, name, status, updated, additional_present) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(arn, position) DO UPDATE SET name=excluded.name, status=excluded.status, updated=excluded.updated, additional_present=excluded.additional_present;

-- name: ListFeatures :many
SELECT * FROM guardduty_features WHERE arn=? ORDER BY position;

-- name: DeleteFeatures :exec
DELETE FROM guardduty_features WHERE arn=?;

-- name: PutAdditionalFeature :exec
INSERT INTO guardduty_additional_features (arn, feature_position, position, name, status, updated) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(arn, feature_position, position) DO UPDATE SET name=excluded.name, status=excluded.status, updated=excluded.updated;

-- name: ListAdditionalFeatures :many
SELECT * FROM guardduty_additional_features WHERE arn=? ORDER BY feature_position, position;

-- name: PutFilterTag :exec
INSERT INTO guardduty_filter_tags (arn, tag_key, tag_value) VALUES (?, ?, ?)
ON CONFLICT(arn, tag_key) DO UPDATE SET tag_value=excluded.tag_value;

-- name: ListFilterTags :many
SELECT * FROM guardduty_filter_tags WHERE arn=? ORDER BY tag_key;

-- name: DeleteFilterTags :exec
DELETE FROM guardduty_filter_tags WHERE arn=?;

-- name: PutFilterCondition :exec
INSERT INTO guardduty_filter_conditions (arn, criterion, greater_than, greater_than_or_equal, gt, gte, less_than, less_than_or_equal, lt, lte, eq_present, equals_present, neq_present, not_equals_present, matches_present, not_matches_present) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(arn, criterion) DO UPDATE SET greater_than=excluded.greater_than, greater_than_or_equal=excluded.greater_than_or_equal, gt=excluded.gt, gte=excluded.gte, less_than=excluded.less_than, less_than_or_equal=excluded.less_than_or_equal, lt=excluded.lt, lte=excluded.lte, eq_present=excluded.eq_present, equals_present=excluded.equals_present, neq_present=excluded.neq_present, not_equals_present=excluded.not_equals_present, matches_present=excluded.matches_present, not_matches_present=excluded.not_matches_present;

-- name: ListFilterConditions :many
SELECT * FROM guardduty_filter_conditions WHERE arn=? ORDER BY criterion;

-- name: DeleteFilterConditions :exec
DELETE FROM guardduty_filter_conditions WHERE arn=?;

-- name: PutFilterConditionValue :exec
INSERT INTO guardduty_filter_condition_values (arn, criterion, operator, position, value) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(arn, criterion, operator, position) DO UPDATE SET value=excluded.value;

-- name: ListFilterConditionValues :many
SELECT * FROM guardduty_filter_condition_values WHERE arn=? ORDER BY criterion, operator, position;
