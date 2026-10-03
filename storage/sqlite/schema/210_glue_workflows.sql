CREATE TABLE glue_workflow (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  created INTEGER NOT NULL,
  modified INTEGER NOT NULL,
  max_concurrent INTEGER,
  PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE glue_workflow_tag (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_value TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, name, item_key),
  FOREIGN KEY (partition, account_id, region, name) REFERENCES glue_workflow (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE glue_workflow_property (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_value TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, name, item_key),
  FOREIGN KEY (partition, account_id, region, name) REFERENCES glue_workflow (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE glue_trigger (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  trigger_type TEXT NOT NULL,
  state TEXT NOT NULL,
  description TEXT,
  schedule TEXT,
  workflow_name TEXT,
  predicate_logical TEXT,
  predicate_present BOOLEAN NOT NULL,
  next_fire INTEGER,
  PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE glue_trigger_tag (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_value TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, name, item_key),
  FOREIGN KEY (partition, account_id, region, name) REFERENCES glue_trigger (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE glue_trigger_action (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  job_name TEXT,
  crawler_name TEXT,
  security_configuration TEXT,
  timeout INTEGER,
  notification_delay INTEGER,
  PRIMARY KEY (partition, account_id, region, name, ordinal),
  FOREIGN KEY (partition, account_id, region, name) REFERENCES glue_trigger (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE glue_trigger_argument (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  item_key TEXT NOT NULL,
  item_value TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, name, ordinal, item_key),
  FOREIGN KEY (partition, account_id, region, name, ordinal) REFERENCES glue_trigger_action (partition, account_id, region, name, ordinal) ON DELETE CASCADE
);

CREATE TABLE glue_trigger_condition (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  job_name TEXT,
  crawler_name TEXT,
  state TEXT,
  crawl_state TEXT,
  logical_operator TEXT,
  PRIMARY KEY (partition, account_id, region, name, ordinal),
  FOREIGN KEY (partition, account_id, region, name) REFERENCES glue_trigger (partition, account_id, region, name) ON DELETE CASCADE
);

CREATE TABLE glue_security_configuration (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  created INTEGER NOT NULL,
  s3_mode TEXT,
  s3_key TEXT,
  logs_mode TEXT,
  logs_key TEXT,
  bookmarks_mode TEXT,
  bookmarks_key TEXT,
  PRIMARY KEY (partition, account_id, region, name)
);

CREATE TABLE glue_workflow_run (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  run_id TEXT NOT NULL,
  previous_run_id TEXT NOT NULL,
  root_trigger TEXT NOT NULL,
  status TEXT NOT NULL,
  error TEXT NOT NULL,
  started INTEGER NOT NULL,
  completed INTEGER,
  next_poll INTEGER,
  PRIMARY KEY (partition, account_id, region, name, run_id)
);

CREATE TABLE glue_workflow_run_property (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  run_id TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_value TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, name, run_id, item_key),
  FOREIGN KEY (partition, account_id, region, name, run_id) REFERENCES glue_workflow_run (partition, account_id, region, name, run_id) ON DELETE CASCADE
);

CREATE TABLE glue_workflow_node (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  run_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  kind TEXT NOT NULL,
  node_name TEXT NOT NULL,
  trigger_name TEXT NOT NULL,
  trigger_type TEXT NOT NULL,
  trigger_state TEXT NOT NULL,
  trigger_description TEXT NOT NULL,
  trigger_schedule TEXT NOT NULL,
  child_run_id TEXT NOT NULL,
  state TEXT NOT NULL,
  error TEXT NOT NULL,
  logical TEXT NOT NULL,
  activated BOOLEAN NOT NULL,
  job_name TEXT,
  crawler_name TEXT,
  security_configuration TEXT,
  timeout INTEGER,
  notification_delay INTEGER,
  PRIMARY KEY (partition, account_id, region, name, run_id, node_id),
  FOREIGN KEY (partition, account_id, region, name, run_id) REFERENCES glue_workflow_run (partition, account_id, region, name, run_id) ON DELETE CASCADE
);

CREATE TABLE glue_workflow_node_argument (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  run_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_value TEXT NOT NULL,
  PRIMARY KEY (partition, account_id, region, name, run_id, node_id, item_key),
  FOREIGN KEY (partition, account_id, region, name, run_id, node_id) REFERENCES glue_workflow_node (partition, account_id, region, name, run_id, node_id) ON DELETE CASCADE
);

CREATE TABLE glue_workflow_node_condition (
  partition TEXT NOT NULL,
  account_id TEXT NOT NULL,
  region TEXT NOT NULL,
  name TEXT NOT NULL,
  run_id TEXT NOT NULL,
  node_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  job_name TEXT,
  crawler_name TEXT,
  state TEXT,
  crawl_state TEXT,
  logical_operator TEXT,
  PRIMARY KEY (partition, account_id, region, name, run_id, node_id, ordinal),
  FOREIGN KEY (partition, account_id, region, name, run_id, node_id) REFERENCES glue_workflow_node (partition, account_id, region, name, run_id, node_id) ON DELETE CASCADE
);
CREATE INDEX glue_workflow_run_due ON glue_workflow_run(next_poll) WHERE next_poll IS NOT NULL;
CREATE INDEX glue_trigger_due ON glue_trigger(next_fire) WHERE next_fire IS NOT NULL;
