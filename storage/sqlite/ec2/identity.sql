-- name: GetIdentitySigningKey :one
SELECT kind, private_key_der, certificate_der FROM ec2_identity_signing_keys WHERE kind = ?;

-- name: PutIdentitySigningKey :exec
INSERT INTO ec2_identity_signing_keys (kind, private_key_der, certificate_der)
VALUES (?, ?, ?)
ON CONFLICT (kind) DO UPDATE SET private_key_der = excluded.private_key_der, certificate_der = excluded.certificate_der;
