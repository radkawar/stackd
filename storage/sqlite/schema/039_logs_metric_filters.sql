CREATE TABLE logs_metric_filters (
 group_id TEXT NOT NULL REFERENCES logs_groups(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 pattern TEXT NOT NULL,
 metric_namespace TEXT NOT NULL,
 metric_name TEXT NOT NULL,
 metric_value TEXT NOT NULL,
 unit TEXT NOT NULL,
 default_value REAL,
 apply_on_transformed_logs INTEGER NOT NULL,
 field_selection TEXT NOT NULL,
 created INTEGER NOT NULL,
 PRIMARY KEY (group_id, name)
);
CREATE TABLE logs_metric_filter_dimensions (
 group_id TEXT NOT NULL,
 filter_name TEXT NOT NULL,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY (group_id, filter_name, name),
 FOREIGN KEY (group_id, filter_name) REFERENCES logs_metric_filters(group_id, name) ON DELETE CASCADE
);
CREATE TABLE logs_metric_filter_system_fields (
 group_id TEXT NOT NULL,
 filter_name TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 field TEXT NOT NULL,
 PRIMARY KEY (group_id, filter_name, ordinal),
 FOREIGN KEY (group_id, filter_name) REFERENCES logs_metric_filters(group_id, name) ON DELETE CASCADE
);
