-- Rebuild typed deployment ownership before dropping the old parent. Existing rows
-- remain version zero; invocation history, archives and metric statistics are retained.
ALTER TABLE lambda_functions RENAME TO lambda_functions_unqualified;
ALTER TABLE lambda_function_variables RENAME TO lambda_function_variables_unqualified;
ALTER TABLE lambda_function_tags RENAME TO lambda_function_tags_unqualified;
ALTER TABLE lambda_function_policies RENAME TO lambda_function_policies_unqualified;
ALTER TABLE lambda_function_policy_principals RENAME TO lambda_function_policy_principals_unqualified;
ALTER TABLE lambda_event_invoke_configs RENAME TO lambda_event_invoke_configs_unqualified;
ALTER TABLE lambda_function_concurrency RENAME TO lambda_function_concurrency_unqualified;
ALTER TABLE lambda_metric_samples RENAME TO lambda_metric_samples_unqualified;

CREATE TABLE lambda_functions (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, name TEXT NOT NULL,
 pending BOOLEAN NOT NULL, version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0 AND (version = 0 OR pending = false)),
 runtime TEXT NOT NULL, handler TEXT NOT NULL, role TEXT NOT NULL, description TEXT NOT NULL, architecture TEXT NOT NULL,
 code_sha256 TEXT NOT NULL, timeout INTEGER NOT NULL, memory_mb INTEGER NOT NULL, ephemeral_mb INTEGER NOT NULL,
 revision TEXT NOT NULL, modified TIMESTAMP NOT NULL,
 state TEXT NOT NULL, state_reason TEXT NOT NULL, state_reason_code TEXT NOT NULL,
 update_status TEXT NOT NULL, update_reason TEXT NOT NULL, dead_letter_arn TEXT NOT NULL DEFAULT '',
 deployment_revision TEXT NOT NULL DEFAULT '', code_size INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(partition,account,region,name,pending,version)
);
INSERT INTO lambda_functions(partition,account,region,name,pending,runtime,handler,role,description,architecture,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason,dead_letter_arn,deployment_revision,code_size) SELECT partition,account,region,name,pending,runtime,handler,role,description,architecture,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason,dead_letter_arn,deployment_revision,code_size FROM lambda_functions_unqualified;
CREATE TABLE lambda_function_variables (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL, version INTEGER NOT NULL DEFAULT 0, key TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,pending,version,key),
 FOREIGN KEY(partition,account,region,function_name,pending,version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
INSERT INTO lambda_function_variables(partition,account,region,function_name,pending,key,value)
 SELECT partition,account,region,function_name,pending,key,value FROM lambda_function_variables_unqualified;
CREATE TABLE lambda_function_tags (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL, version INTEGER NOT NULL DEFAULT 0 CHECK(version = 0), key TEXT NOT NULL, value TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,pending,version,key),
 FOREIGN KEY(partition,account,region,function_name,pending,version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
INSERT INTO lambda_function_tags(partition,account,region,function_name,pending,key,value)
 SELECT partition,account,region,function_name,pending,key,value FROM lambda_function_tags_unqualified;
CREATE TABLE lambda_function_policies (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false), deployment_version INTEGER NOT NULL DEFAULT 0 CHECK(deployment_version = 0),
 qualifier TEXT NOT NULL DEFAULT '', document TEXT NOT NULL, revision TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,qualifier), FOREIGN KEY(partition,account,region,function_name,pending,deployment_version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
INSERT INTO lambda_function_policies(partition,account,region,function_name,document,revision)
 SELECT partition,account,region,function_name,document,revision FROM lambda_function_policies_unqualified;
CREATE TABLE lambda_function_policy_principals (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 qualifier TEXT NOT NULL DEFAULT '', principal TEXT NOT NULL, principal_id TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,qualifier,principal),
 FOREIGN KEY(partition,account,region,function_name,qualifier) REFERENCES lambda_function_policies(partition,account,region,function_name,qualifier) ON DELETE CASCADE
);
INSERT INTO lambda_function_policy_principals(partition,account,region,function_name,principal,principal_id)
 SELECT partition,account,region,function_name,principal,principal_id FROM lambda_function_policy_principals_unqualified;
CREATE TABLE lambda_event_invoke_configs (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false), deployment_version INTEGER NOT NULL DEFAULT 0 CHECK(deployment_version = 0),
 qualifier TEXT NOT NULL DEFAULT '', modified TIMESTAMP NOT NULL,
 max_age_seconds INTEGER NOT NULL, max_retries INTEGER NOT NULL, has_max_age BOOLEAN NOT NULL, has_max_retries BOOLEAN NOT NULL,
 effective_max_age_seconds INTEGER NOT NULL, effective_max_retries INTEGER NOT NULL,
 applies_at TIMESTAMP, version INTEGER NOT NULL, deleted BOOLEAN NOT NULL,
 on_success_arn TEXT NOT NULL DEFAULT '', on_failure_arn TEXT NOT NULL DEFAULT '',
 effective_on_success_arn TEXT NOT NULL DEFAULT '', effective_on_failure_arn TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(partition,account,region,function_name,qualifier), FOREIGN KEY(partition,account,region,function_name,pending,deployment_version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
INSERT INTO lambda_event_invoke_configs(partition,account,region,function_name,pending,modified,max_age_seconds,max_retries,has_max_age,has_max_retries,effective_max_age_seconds,effective_max_retries,applies_at,version,deleted,on_success_arn,on_failure_arn,effective_on_success_arn,effective_on_failure_arn) SELECT partition,account,region,function_name,pending,modified,max_age_seconds,max_retries,has_max_age,has_max_retries,effective_max_age_seconds,effective_max_retries,applies_at,version,deleted,on_success_arn,on_failure_arn,effective_on_success_arn,effective_on_failure_arn FROM lambda_event_invoke_configs_unqualified;
CREATE TABLE lambda_function_concurrency (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false), deployment_version INTEGER NOT NULL DEFAULT 0 CHECK(deployment_version = 0),
 reserved_concurrency INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,function_name), FOREIGN KEY(partition,account,region,function_name,pending,deployment_version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
INSERT INTO lambda_function_concurrency(partition,account,region,function_name,reserved_concurrency)
 SELECT partition,account,region,function_name,reserved_concurrency FROM lambda_function_concurrency_unqualified;
CREATE TABLE lambda_aliases (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false), deployment_version INTEGER NOT NULL DEFAULT 0 CHECK(deployment_version = 0),
 qualifier TEXT NOT NULL, function_version INTEGER NOT NULL, additional_version INTEGER NOT NULL,
 additional_weight REAL NOT NULL, description TEXT NOT NULL, revision TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,qualifier), FOREIGN KEY(partition,account,region,function_name,pending,deployment_version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
-- Deliberately no deployment foreign key: scoped allocation survives deletion.
CREATE TABLE lambda_version_allocations (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 last_version INTEGER NOT NULL CHECK(last_version > 0), PRIMARY KEY(partition,account,region,function_name)
);
CREATE TABLE lambda_metric_samples (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 resource TEXT NOT NULL DEFAULT '', executed_version TEXT NOT NULL DEFAULT '',
 minute TIMESTAMP NOT NULL, metric_name TEXT NOT NULL, value INTEGER NOT NULL, sample_count INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,resource,executed_version,minute,metric_name,value)
);
INSERT INTO lambda_metric_samples(partition,account,region,function_name,minute,metric_name,value,sample_count)
 SELECT partition,account,region,function_name,minute,metric_name,value,sample_count FROM lambda_metric_samples_unqualified;
DROP TABLE lambda_metric_samples_unqualified;
DROP TABLE lambda_function_concurrency_unqualified;
DROP TABLE lambda_event_invoke_configs_unqualified;
DROP TABLE lambda_function_policy_principals_unqualified;
DROP TABLE lambda_function_policies_unqualified;
DROP TABLE lambda_function_tags_unqualified;
DROP TABLE lambda_function_variables_unqualified;
DROP TABLE lambda_functions_unqualified;
CREATE INDEX lambda_functions_code_archive ON lambda_functions(partition,account,region,code_sha256);
CREATE INDEX lambda_event_invoke_configs_due ON lambda_event_invoke_configs(applies_at,partition,region,account,function_name,qualifier) WHERE applies_at IS NOT NULL;
CREATE INDEX lambda_metric_samples_due ON lambda_metric_samples(minute,partition,account,region,function_name,resource,executed_version);

-- Accepted work retains the last applied delivery controls independently of its
-- target. Only unfinished historical work acquires authority from current state;
-- completed records keep their recorded role and terminal history.
ALTER TABLE lambda_invocations ADD COLUMN max_age_seconds INTEGER NOT NULL DEFAULT 21600;
ALTER TABLE lambda_invocations ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 2;
ALTER TABLE lambda_invocations ADD COLUMN on_success_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_invocations ADD COLUMN on_failure_arn TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_invocations ADD COLUMN dead_letter_arn TEXT NOT NULL DEFAULT '';
UPDATE lambda_invocations AS i SET
 max_age_seconds=COALESCE((SELECT c.effective_max_age_seconds FROM lambda_event_invoke_configs AS c WHERE c.partition=i.partition AND c.account=i.account AND c.region=i.region AND c.function_name=i.function_name AND c.qualifier=''),21600),
 max_retries=COALESCE((SELECT c.effective_max_retries FROM lambda_event_invoke_configs AS c WHERE c.partition=i.partition AND c.account=i.account AND c.region=i.region AND c.function_name=i.function_name AND c.qualifier=''),2),
 on_success_arn=COALESCE((SELECT c.effective_on_success_arn FROM lambda_event_invoke_configs AS c WHERE c.partition=i.partition AND c.account=i.account AND c.region=i.region AND c.function_name=i.function_name AND c.qualifier=''),''),
 on_failure_arn=COALESCE((SELECT c.effective_on_failure_arn FROM lambda_event_invoke_configs AS c WHERE c.partition=i.partition AND c.account=i.account AND c.region=i.region AND c.function_name=i.function_name AND c.qualifier=''),''),
 role_arn=CASE WHEN role_arn='' THEN COALESCE((SELECT f.role FROM lambda_functions AS f WHERE f.partition=i.partition AND f.account=i.account AND f.region=i.region AND f.name=i.function_name AND f.pending=false AND f.version=0),'') ELSE role_arn END,
 dead_letter_arn=COALESCE((SELECT f.dead_letter_arn FROM lambda_functions AS f WHERE f.partition=i.partition AND f.account=i.account AND f.region=i.region AND f.name=i.function_name AND f.pending=false AND f.version=0),'')
WHERE state!='completed';
