ALTER TABLE org_invitation_events RENAME TO org_handshake_events;
ALTER TABLE org_handshake_events ADD COLUMN action TEXT NOT NULL DEFAULT 'INVITE';
ALTER TABLE org_handshake_events ADD COLUMN parent_id TEXT NOT NULL DEFAULT '';
UPDATE kernel_events SET event_type = 'organizations.handshake.changed.v1'
WHERE event_type = 'organizations.invitation.changed.v1';
