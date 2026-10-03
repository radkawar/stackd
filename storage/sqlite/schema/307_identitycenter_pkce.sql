ALTER TABLE identitycenter_clients ADD COLUMN issuer_url TEXT NOT NULL DEFAULT '';
CREATE TABLE identitycenter_client_redirect_uris (
    client_id TEXT NOT NULL REFERENCES identitycenter_clients(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    uri TEXT NOT NULL,
    PRIMARY KEY(client_id, position)
);
CREATE TABLE identitycenter_authorizations (
    id TEXT PRIMARY KEY NOT NULL,
    code_hash TEXT NOT NULL,
    client_id TEXT NOT NULL,
    instance_arn TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    oauth_state TEXT NOT NULL,
    csrf TEXT NOT NULL,
    state TEXT NOT NULL,
    created DATETIME NOT NULL,
    expires DATETIME NOT NULL
);
CREATE UNIQUE INDEX identitycenter_authorizations_code ON identitycenter_authorizations(code_hash) WHERE code_hash <> '';
