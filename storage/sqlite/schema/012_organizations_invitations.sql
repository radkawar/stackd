-- Invitations outlive their source organization for the handshake retention
-- window; the partition remains their storage boundary.
CREATE TABLE org_invitations (
    partition TEXT NOT NULL REFERENCES org_partitions(partition) ON DELETE CASCADE,
    id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    management_account_id TEXT NOT NULL,
    management_name TEXT NOT NULL,
    management_email TEXT NOT NULL,
    feature_set TEXT NOT NULL,
    target_account_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target TEXT NOT NULL,
    notes TEXT NOT NULL,
    state TEXT NOT NULL,
    requested_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    terminal_at TIMESTAMP NOT NULL,
    request_id TEXT NOT NULL,
    request_region TEXT NOT NULL,
    actor_arn TEXT NOT NULL,
    PRIMARY KEY (partition, id)
);
CREATE TABLE org_invitation_tags (
    partition TEXT NOT NULL,
    invitation_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (partition, invitation_id, key),
    FOREIGN KEY (partition, invitation_id) REFERENCES org_invitations(partition, id) ON DELETE CASCADE
);
