-- URL ownership follows the base function, never the mutable alias row.
CREATE TABLE lambda_function_urls (
 partition TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, function_name TEXT NOT NULL,
 pending BOOLEAN NOT NULL DEFAULT false CHECK(pending = false), deployment_version INTEGER NOT NULL DEFAULT 0 CHECK(deployment_version = 0),
 qualifier TEXT NOT NULL DEFAULT '', id TEXT NOT NULL UNIQUE,
 created TIMESTAMP NOT NULL, modified TIMESTAMP NOT NULL, applies_at TIMESTAMP NOT NULL,
 auth_type TEXT NOT NULL, invoke_mode TEXT NOT NULL, cors_present BOOLEAN NOT NULL,
 allow_credentials BOOLEAN, allow_headers TEXT, allow_methods TEXT, allow_origins TEXT, expose_headers TEXT, max_age INTEGER,
 effective_auth_type TEXT NOT NULL, effective_invoke_mode TEXT NOT NULL, effective_cors_present BOOLEAN NOT NULL,
 effective_allow_credentials BOOLEAN, effective_allow_headers TEXT, effective_allow_methods TEXT, effective_allow_origins TEXT, effective_expose_headers TEXT, effective_max_age INTEGER,
 PRIMARY KEY(partition,account,region,function_name,qualifier),
 FOREIGN KEY(partition,account,region,function_name,pending,deployment_version) REFERENCES lambda_functions(partition,account,region,name,pending,version) ON DELETE CASCADE
);
