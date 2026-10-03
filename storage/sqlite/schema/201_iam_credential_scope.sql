ALTER TABLE iam_credential ADD COLUMN credential_in_scope_of_issuer_type TEXT NOT NULL DEFAULT '';
ALTER TABLE iam_credential ADD COLUMN credential_in_scope_of_credentials_issued_to TEXT NOT NULL DEFAULT '';
