-- Historical aggregates have no forwarding witness and remain unavailable.
ALTER TABLE ec2_flow_log_aggregates
 ADD COLUMN traffic_path INTEGER NOT NULL DEFAULT 0 CHECK (traffic_path IN (0, 1));
