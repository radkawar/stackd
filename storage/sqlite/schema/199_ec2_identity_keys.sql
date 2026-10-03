-- Local operational signing authority, not an AWS account or resource identity.
CREATE TABLE ec2_identity_signing_keys (
    kind TEXT PRIMARY KEY NOT NULL,
    private_key_der BLOB NOT NULL,
    certificate_der BLOB NOT NULL
);
