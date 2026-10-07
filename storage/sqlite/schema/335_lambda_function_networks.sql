CREATE TABLE lambda_function_networks (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
 function_name TEXT NOT NULL, pending BOOLEAN NOT NULL, version INTEGER NOT NULL,
 incarnation TEXT NOT NULL, vpc_id TEXT NOT NULL,
 PRIMARY KEY (partition,account,region,function_name,pending,version),
 FOREIGN KEY (partition,account,region,function_name,pending,version)
 REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
CREATE TABLE lambda_function_network_members (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
 function_name TEXT NOT NULL, pending BOOLEAN NOT NULL, version INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK (kind IN ('subnet','security-group')),
 position INTEGER NOT NULL, resource_id TEXT NOT NULL,
 PRIMARY KEY (partition,account,region,function_name,pending,version,kind,position),
 FOREIGN KEY (partition,account,region,function_name,pending,version)
 REFERENCES lambda_function_networks(partition,account,region,function_name,pending,version) ON DELETE CASCADE
);
