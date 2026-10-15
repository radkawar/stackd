CREATE TABLE msk_cluster_network_options (
    arn TEXT PRIMARY KEY REFERENCES msk_clusters(arn) ON DELETE CASCADE,
    default_metrics INTEGER NOT NULL CHECK (default_metrics IN (0, 1))
);
CREATE TABLE msk_cluster_subnets (
    arn TEXT NOT NULL REFERENCES msk_clusters(arn) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    subnet_id TEXT NOT NULL,
    PRIMARY KEY (arn, ordinal),
    UNIQUE (arn, subnet_id)
);
CREATE TABLE msk_cluster_security_groups (
    arn TEXT NOT NULL REFERENCES msk_clusters(arn) ON DELETE CASCADE,
    security_group_id TEXT NOT NULL,
    PRIMARY KEY (arn, security_group_id)
);
CREATE TABLE msk_broker_networks (
    arn TEXT NOT NULL REFERENCES msk_clusters(arn) ON DELETE CASCADE,
    broker_id INTEGER NOT NULL CHECK (broker_id > 0),
    interface_id TEXT NOT NULL,
    subnet_id TEXT NOT NULL,
    availability_zone TEXT NOT NULL,
    network_id TEXT NOT NULL,
    PRIMARY KEY (arn, broker_id),
    UNIQUE (interface_id)
);
