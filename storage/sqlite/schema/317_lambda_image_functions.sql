CREATE TABLE lambda_function_images (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
 function_name TEXT NOT NULL, pending BOOLEAN NOT NULL, version INTEGER NOT NULL,
 image_uri TEXT NOT NULL, image_id TEXT NOT NULL, resolved_image_uri TEXT NOT NULL,
 image_size INTEGER NOT NULL, entrypoint TEXT NOT NULL, command TEXT NOT NULL,
 environment TEXT NOT NULL, working_directory TEXT NOT NULL, image_config TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,pending,version),
 FOREIGN KEY(partition,account,region,function_name,pending,version)
 REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);

CREATE TABLE lambda_function_owners (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
 function_name TEXT NOT NULL, pending BOOLEAN NOT NULL, version INTEGER NOT NULL,
 stack_id TEXT NOT NULL, logical_id TEXT NOT NULL, token TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,pending,version),
 FOREIGN KEY(partition,account,region,function_name,pending,version)
 REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
