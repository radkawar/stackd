-- name: GetWebACL :one
SELECT * FROM wafv2_web_acls WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: ListWebACLs :many
SELECT * FROM wafv2_web_acls WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY name, id;
-- name: PutWebACL :exec
INSERT INTO wafv2_web_acls(partition, account_id, region, arn, name, id, description, lock_token, definition, capacity, created, updated, owner_stack_id, owner_logical_id, owner_token)
VALUES(sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(name), sqlc.arg(id), sqlc.arg(description), sqlc.arg(lock_token), sqlc.arg(definition), sqlc.arg(capacity), sqlc.arg(created), sqlc.arg(updated), sqlc.arg(owner_stack_id), sqlc.arg(owner_logical_id), sqlc.arg(owner_token))
ON CONFLICT(partition, account_id, region, arn) DO UPDATE SET description = excluded.description, lock_token = excluded.lock_token, definition = excluded.definition, capacity = excluded.capacity, updated = excluded.updated, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;
-- name: DeleteWebACL :exec
DELETE FROM wafv2_web_acls WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: ListWebACLTags :many
SELECT tag_key, tag_value FROM wafv2_web_acl_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn) ORDER BY tag_key;
-- name: DeleteWebACLTags :exec
DELETE FROM wafv2_web_acl_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: PutWebACLTag :exec
INSERT INTO wafv2_web_acl_tags(partition, account_id, region, arn, tag_key, tag_value) VALUES(sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(tag_key), sqlc.arg(tag_value));

-- name: GetIPSet :one
SELECT * FROM wafv2_ip_sets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: ListIPSets :many
SELECT * FROM wafv2_ip_sets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) ORDER BY name, id;
-- name: PutIPSet :exec
INSERT INTO wafv2_ip_sets(partition, account_id, region, arn, name, id, description, lock_token, ip_address_version, addresses, created, updated, owner_stack_id, owner_logical_id, owner_token)
VALUES(sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(name), sqlc.arg(id), sqlc.arg(description), sqlc.arg(lock_token), sqlc.arg(ip_address_version), sqlc.arg(addresses), sqlc.arg(created), sqlc.arg(updated), sqlc.arg(owner_stack_id), sqlc.arg(owner_logical_id), sqlc.arg(owner_token))
ON CONFLICT(partition, account_id, region, arn) DO UPDATE SET description = excluded.description, lock_token = excluded.lock_token, addresses = excluded.addresses, updated = excluded.updated, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token;
-- name: DeleteIPSet :exec
DELETE FROM wafv2_ip_sets WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: ListIPSetTags :many
SELECT tag_key, tag_value FROM wafv2_ip_set_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn) ORDER BY tag_key;
-- name: DeleteIPSetTags :exec
DELETE FROM wafv2_ip_set_tags WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND arn = sqlc.arg(arn);
-- name: PutIPSetTag :exec
INSERT INTO wafv2_ip_set_tags(partition, account_id, region, arn, tag_key, tag_value) VALUES(sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(arn), sqlc.arg(tag_key), sqlc.arg(tag_value));

-- name: GetAssociation :one
SELECT * FROM wafv2_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_arn = sqlc.arg(resource_arn);
-- name: ListAssociations :many
SELECT * FROM wafv2_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND web_acl_arn = sqlc.arg(web_acl_arn) ORDER BY resource_arn;
-- name: PutAssociation :exec
INSERT INTO wafv2_associations(partition, account_id, region, resource_arn, web_acl_arn, resource_incarnation, owner_stack_id, owner_logical_id, owner_token, created)
VALUES(sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(resource_arn), sqlc.arg(web_acl_arn), sqlc.arg(resource_incarnation), sqlc.arg(owner_stack_id), sqlc.arg(owner_logical_id), sqlc.arg(owner_token), sqlc.arg(created))
ON CONFLICT(partition, account_id, region, resource_arn) DO UPDATE SET web_acl_arn = excluded.web_acl_arn, resource_incarnation = excluded.resource_incarnation, owner_stack_id = excluded.owner_stack_id, owner_logical_id = excluded.owner_logical_id, owner_token = excluded.owner_token, created = excluded.created;
-- name: DeleteAssociation :exec
DELETE FROM wafv2_associations WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND resource_arn = sqlc.arg(resource_arn);

-- name: NextMetricPublication :one
SELECT partition, account_id, region, web_acl, rule, minute FROM wafv2_metric_samples ORDER BY minute, partition, account_id, region, web_acl, rule LIMIT 1;
-- name: ListMetricSamples :many
SELECT metric_name, count FROM wafv2_metric_samples WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND web_acl = sqlc.arg(web_acl) AND rule = sqlc.arg(rule) AND minute = sqlc.arg(minute) ORDER BY metric_name;
-- name: AddMetricSample :exec
INSERT INTO wafv2_metric_samples(partition, account_id, region, web_acl, rule, minute, metric_name, count)
VALUES(sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(web_acl), sqlc.arg(rule), sqlc.arg(minute), sqlc.arg(metric_name), sqlc.arg(count))
ON CONFLICT(partition, account_id, region, web_acl, rule, minute, metric_name) DO UPDATE SET count = wafv2_metric_samples.count + excluded.count;
-- name: DeleteMetricPublication :exec
DELETE FROM wafv2_metric_samples WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND web_acl = sqlc.arg(web_acl) AND rule = sqlc.arg(rule) AND minute = sqlc.arg(minute);

-- name: ListSampledRequests :many
SELECT * FROM wafv2_sampled_requests WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND web_acl_arn = sqlc.arg(web_acl_arn) AND metric_name = sqlc.arg(metric_name) AND at >= sqlc.arg(start_at) AND at < sqlc.arg(end_at) ORDER BY at, sequence LIMIT sqlc.arg(max_items);
-- name: CountSampledRequests :one
SELECT COUNT(*) FROM wafv2_sampled_requests WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND web_acl_arn = sqlc.arg(web_acl_arn) AND metric_name = sqlc.arg(metric_name) AND at >= sqlc.arg(since);
-- name: PutSampledRequest :exec
INSERT INTO wafv2_sampled_requests(partition, account_id, region, web_acl_arn, metric_name, at, sequence, sample)
VALUES(sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(web_acl_arn), sqlc.arg(metric_name), sqlc.arg(at), sqlc.arg(sequence), sqlc.arg(sample));
-- name: PruneSampledRequests :exec
DELETE FROM wafv2_sampled_requests WHERE at < sqlc.arg(cutoff);
-- name: SumSamplePopulation :one
SELECT CAST(COALESCE(SUM(population), 0) AS INTEGER) FROM wafv2_sample_population WHERE partition = sqlc.arg(partition) AND account_id = sqlc.arg(account_id) AND region = sqlc.arg(region) AND web_acl_arn = sqlc.arg(web_acl_arn) AND metric_name = sqlc.arg(metric_name) AND minute >= sqlc.arg(start_minute) AND minute < sqlc.arg(end_at);
-- name: AddSamplePopulation :exec
INSERT INTO wafv2_sample_population(partition, account_id, region, web_acl_arn, metric_name, minute, population)
VALUES(sqlc.arg(partition), sqlc.arg(account_id), sqlc.arg(region), sqlc.arg(web_acl_arn), sqlc.arg(metric_name), sqlc.arg(minute), sqlc.arg(population))
ON CONFLICT(partition, account_id, region, web_acl_arn, metric_name, minute) DO UPDATE SET population = wafv2_sample_population.population + excluded.population;
-- name: PruneSamplePopulation :exec
DELETE FROM wafv2_sample_population WHERE minute < sqlc.arg(cutoff);
