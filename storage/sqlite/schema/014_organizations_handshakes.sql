ALTER TABLE org_invitations RENAME TO org_handshakes;
ALTER TABLE org_invitation_tags RENAME TO org_handshake_tags;
ALTER TABLE org_handshake_tags RENAME COLUMN invitation_id TO handshake_id;
ALTER TABLE org_handshakes ADD COLUMN action TEXT NOT NULL DEFAULT 'INVITE';
ALTER TABLE org_handshakes ADD COLUMN parent_id TEXT NOT NULL DEFAULT '';
-- A migration can outlive the 30-day retention of its accepted child handshakes.
-- Consent belongs to the migration until it finishes, expires or is canceled.
CREATE TABLE org_handshake_approvals (
    partition TEXT NOT NULL,
    handshake_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    approved BOOLEAN NOT NULL,
    PRIMARY KEY (partition, handshake_id, account_id),
    FOREIGN KEY (partition, handshake_id) REFERENCES org_handshakes(partition, id) ON DELETE CASCADE
);
