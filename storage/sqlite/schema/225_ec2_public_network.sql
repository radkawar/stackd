CREATE TABLE ec2_public_addresses (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    automatic BOOLEAN NOT NULL,
    public_ip TEXT,
    association_id TEXT,
    network_interface_id TEXT,
    private_ip_address TEXT,
    network_border_group TEXT NOT NULL,
    tags_present BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account_id, region, resource_id),
    UNIQUE (public_ip),
    CHECK (public_ip IS NULL OR (
        substr(public_ip, 1, 7) IN ('198.18.', '198.19.')
        AND public_ip NOT IN ('198.18.0.0', '198.19.255.255')
    ))
);
CREATE INDEX ec2_public_address_interface ON ec2_public_addresses (partition, account_id, region, network_interface_id);
CREATE TABLE ec2_public_address_tags (
    partition TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    key TEXT,
    value TEXT,
    PRIMARY KEY (partition, account_id, region, resource_id, position),
    FOREIGN KEY (partition, account_id, region, resource_id) REFERENCES ec2_public_addresses (partition, account_id, region, resource_id) ON DELETE CASCADE
);

-- Existing ECS public intent must acquire real reservations at the cutover.
-- Allocate across every scope together because native host addresses are shared.
INSERT INTO ec2_public_addresses (
    partition, account_id, region, resource_id, automatic, public_ip,
    network_interface_id, private_ip_address, network_border_group, tags_present
)
SELECT partition, account_id, region, 'public-auto-migrated-' || resource_id,
       1, printf('198.%d.%d.%d', 18 + ordinal / 65536, ordinal / 256 % 256, ordinal % 256),
       resource_id, private_ip_address, region, 0
FROM (
    SELECT partition, account_id, region, resource_id, private_ip_address,
           row_number() OVER (ORDER BY partition, account_id, region, resource_id) AS ordinal
    FROM ec2_network_interfaces
    WHERE task_owner_arn != '' AND task_public_networking = 1
);
