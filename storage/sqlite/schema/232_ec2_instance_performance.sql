-- Retain native counter cursors and unpublished monitoring-period contributions.
ALTER TABLE ec2_instances ADD COLUMN performance_native_pid INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ec2_instances ADD COLUMN performance_native_start_time_ticks BLOB NOT NULL DEFAULT X'0000000000000000';
ALTER TABLE ec2_instances ADD COLUMN performance_interface_index INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ec2_instances ADD COLUMN performance_cpu_usage INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ec2_instances ADD COLUMN performance_bytes_in BLOB NOT NULL DEFAULT X'0000000000000000';
ALTER TABLE ec2_instances ADD COLUMN performance_bytes_out BLOB NOT NULL DEFAULT X'0000000000000000';
ALTER TABLE ec2_instances ADD COLUMN performance_observed_at DATETIME;
ALTER TABLE ec2_instances ADD COLUMN performance_sample_at DATETIME;
ALTER TABLE ec2_instances ADD COLUMN performance_window_at DATETIME;
ALTER TABLE ec2_instances ADD COLUMN performance_detailed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ec2_instances ADD COLUMN performance_cpu_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ec2_instances ADD COLUMN performance_cpu_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE ec2_instances ADD COLUMN performance_cpu_min REAL NOT NULL DEFAULT 0;
ALTER TABLE ec2_instances ADD COLUMN performance_cpu_max REAL NOT NULL DEFAULT 0;
ALTER TABLE ec2_instances ADD COLUMN performance_network_in BLOB NOT NULL DEFAULT X'0000000000000000';
ALTER TABLE ec2_instances ADD COLUMN performance_network_out BLOB NOT NULL DEFAULT X'0000000000000000';
ALTER TABLE ec2_instances ADD COLUMN performance_network_observed BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE ec2_instance_performance_groups (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    group_name TEXT NOT NULL,
    cpu_count INTEGER NOT NULL,
    cpu_sum REAL NOT NULL,
    cpu_min REAL NOT NULL,
    cpu_max REAL NOT NULL,
    network_in BLOB NOT NULL,
    network_out BLOB NOT NULL,
    network_observed BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, resource_id, group_name),
    FOREIGN KEY (partition, account_id, region, resource_id)
      REFERENCES ec2_instances (partition, account_id, region, resource_id) ON DELETE CASCADE
);
