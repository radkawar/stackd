-- Allocation is independent of the catalog so deleting every version never resets a name.
CREATE TABLE lambda_layer_version_allocations (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, layer_name TEXT NOT NULL,
 last_version INTEGER NOT NULL CHECK(last_version > 0), PRIMARY KEY(partition,account,region,layer_name)
);
CREATE TABLE lambda_layer_versions (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, layer_name TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version > 0), code_sha256 TEXT NOT NULL, code_size INTEGER NOT NULL,
 description TEXT NOT NULL, license_info TEXT NOT NULL, created TIMESTAMP NOT NULL,
 has_compatible_runtimes BOOLEAN NOT NULL, has_compatible_architectures BOOLEAN NOT NULL,
 has_reference BOOLEAN NOT NULL, reference_bucket TEXT NOT NULL, reference_key TEXT NOT NULL, reference_version_id TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,layer_name,version)
);
CREATE INDEX lambda_layer_versions_code_archive ON lambda_layer_versions(partition,account,region,code_sha256);
CREATE TABLE lambda_layer_compatible_runtimes (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, layer_name TEXT NOT NULL,
 version INTEGER NOT NULL, position INTEGER NOT NULL CHECK(position >= 0), runtime TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,layer_name,version,position),
 FOREIGN KEY(partition,account,region,layer_name,version) REFERENCES lambda_layer_versions(partition,account,region,layer_name,version) ON DELETE CASCADE
);
CREATE TABLE lambda_layer_compatible_architectures (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, layer_name TEXT NOT NULL,
 version INTEGER NOT NULL, position INTEGER NOT NULL CHECK(position >= 0), architecture TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,layer_name,version,position),
 FOREIGN KEY(partition,account,region,layer_name,version) REFERENCES lambda_layer_versions(partition,account,region,layer_name,version) ON DELETE CASCADE
);
CREATE TABLE lambda_layer_policies (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, layer_name TEXT NOT NULL,
 version INTEGER NOT NULL, document TEXT NOT NULL, revision TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,layer_name,version),
 FOREIGN KEY(partition,account,region,layer_name,version) REFERENCES lambda_layer_versions(partition,account,region,layer_name,version) ON DELETE CASCADE
);
CREATE TABLE lambda_layer_policy_principals (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, layer_name TEXT NOT NULL,
 version INTEGER NOT NULL, principal TEXT NOT NULL, principal_id TEXT NOT NULL,
 PRIMARY KEY(partition,account,region,layer_name,version,principal),
 FOREIGN KEY(partition,account,region,layer_name,version) REFERENCES lambda_layer_policies(partition,account,region,layer_name,version) ON DELETE CASCADE
);
-- Deployment snapshots retain immutable attachment identity and archive ownership.
-- There is deliberately no catalog foreign key: deleting a layer cannot detach it.
CREATE TABLE lambda_function_layers (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL, version INTEGER NOT NULL, position INTEGER NOT NULL CHECK(position >= 0),
 layer_partition TEXT NOT NULL, layer_account TEXT NOT NULL, layer_region TEXT NOT NULL, layer_name TEXT NOT NULL,
 layer_version INTEGER NOT NULL CHECK(layer_version > 0), code_sha256 TEXT NOT NULL, code_size INTEGER NOT NULL,
 PRIMARY KEY(partition,account,region,function_name,pending,version,position),
 FOREIGN KEY(partition,account,region,function_name,pending,version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
CREATE INDEX lambda_function_layers_code_archive ON lambda_function_layers(layer_partition,layer_account,layer_region,code_sha256);
CREATE INDEX lambda_function_layers_version ON lambda_function_layers(layer_partition,layer_account,layer_region,layer_name,layer_version);
