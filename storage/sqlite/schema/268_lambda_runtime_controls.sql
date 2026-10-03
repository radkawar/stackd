CREATE TABLE lambda_recursion_controls (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
 function_name TEXT NOT NULL, recursive_loop TEXT NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false),
 deployment_version INTEGER NOT NULL DEFAULT 0 CHECK(deployment_version = 0),
 PRIMARY KEY (partition, account, region, function_name),
 FOREIGN KEY (partition,account,region,function_name,pending,deployment_version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
CREATE TABLE lambda_runtime_management (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
 function_name TEXT NOT NULL, version INTEGER NOT NULL, update_runtime_on TEXT NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false),
 PRIMARY KEY (partition, account, region, function_name, version),
 FOREIGN KEY (partition,account,region,function_name,pending,version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
CREATE TABLE lambda_provisioned_concurrency (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
 function_name TEXT NOT NULL, qualifier TEXT NOT NULL,
 requested INTEGER NOT NULL CHECK(requested > 0), generation TEXT NOT NULL,
 status TEXT NOT NULL, status_reason TEXT NOT NULL, modified TIMESTAMP NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false),
 deployment_version INTEGER NOT NULL DEFAULT 0 CHECK(deployment_version = 0),
 PRIMARY KEY (partition, account, region, function_name, qualifier),
 FOREIGN KEY (partition,account,region,function_name,pending,deployment_version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
