ALTER TABLE codepipeline_executions DROP COLUMN request_hash;
ALTER TABLE codepipeline_definitions ADD COLUMN variables_present INTEGER NOT NULL DEFAULT 0;

CREATE TABLE codepipeline_variable_declarations (
 incarnation TEXT NOT NULL,
 version INTEGER NOT NULL,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 default_value TEXT,
 description TEXT,
 PRIMARY KEY (incarnation,version,position)
);

CREATE TABLE codepipeline_execution_variables (
 execution_id TEXT NOT NULL,
 position INTEGER NOT NULL,
 name TEXT NOT NULL,
 resolved_value TEXT NOT NULL,
 PRIMARY KEY (execution_id,position)
);
