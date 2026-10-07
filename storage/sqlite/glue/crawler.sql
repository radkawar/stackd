-- name: GetGlueCrawler :one
SELECT * FROM glue_crawlers WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: ListGlueCrawlers :many
SELECT * FROM glue_crawlers WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: DeleteGlueCrawler :exec
DELETE FROM glue_crawlers WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: PutGlueCrawler :exec
INSERT INTO glue_crawlers (cfn_owner,partition,account_id,region,name,role,database_name,description,table_prefix,configuration,security_configuration,targets,classifiers,schema_change_policy,recrawl_policy,lake_formation,lineage,schedule,tags,state,version,created_at,updated_at,last_crawl,elapsed_ms,run_id,next_scheduled)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,name) DO UPDATE SET role=excluded.role,database_name=excluded.database_name,description=excluded.description,table_prefix=excluded.table_prefix,configuration=excluded.configuration,security_configuration=excluded.security_configuration,targets=excluded.targets,classifiers=excluded.classifiers,schema_change_policy=excluded.schema_change_policy,recrawl_policy=excluded.recrawl_policy,lake_formation=excluded.lake_formation,lineage=excluded.lineage,schedule=excluded.schedule,tags=excluded.tags,state=excluded.state,version=excluded.version,created_at=excluded.created_at,updated_at=excluded.updated_at,last_crawl=excluded.last_crawl,elapsed_ms=excluded.elapsed_ms,run_id=excluded.run_id,next_scheduled=excluded.next_scheduled;
-- name: GetGlueCrawlerRun :one
SELECT * FROM glue_crawler_runs WHERE id = ?;
-- name: ListGlueCrawlerRuns :many
SELECT * FROM glue_crawler_runs WHERE partition = ? AND account_id = ? AND region = ? AND crawler_name = ? ORDER BY started_at DESC,id DESC;
-- name: PendingGlueCrawlerRuns :many
SELECT * FROM glue_crawler_runs WHERE state IN ('RUNNING','CANCELLING') ORDER BY started_at,id;
-- name: PutGlueCrawlerRun :exec
INSERT INTO glue_crawler_runs (id,partition,account_id,region,crawler_name,state,phase,started_at,completed_at,error_message,tables_created,tables_updated,partitions_created,parent_event_id,trigger_name,workflow_name,workflow_run_id)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET state=excluded.state,phase=excluded.phase,completed_at=excluded.completed_at,error_message=excluded.error_message,tables_created=excluded.tables_created,tables_updated=excluded.tables_updated,partitions_created=excluded.partitions_created;
-- name: ScheduledGlueCrawlers :many
SELECT * FROM glue_crawlers WHERE next_scheduled IS NOT NULL ORDER BY next_scheduled,partition,account_id,region,name;
